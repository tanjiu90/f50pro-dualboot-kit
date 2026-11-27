# F50 Pro Dual-Boot Kit (`MU3356` / `UMS9632`)

Turnkey, sanitized, **pure-Python (zero-WSL)** toolkit for backing up, building, flashing, provisioning, and verifying **ZTE F50 Pro** across both hardware variants (**插卡版 `board_id=6`** and **内置双 eSIM 版 `board_id=1`**) with **3 selectable configurations** and **multi-platform host deployment (`Windows`, `Linux`, `macOS`, `Android Termux OTG`)**.

Designed for **one-click per-OS selective download & deployment** and **autonomous AI Agent flashing** (`AGENT-FLASH.md`).

> **新手入门 / 零基础用户**：请直接阅读中文零基础保姆级指南 -> [docs/beginner-guide.md](docs/beginner-guide.md)（手把手教你从装 Python/驱动、备份原厂分区到一键双系统及回退）。

---

## Supported Hardware Variants

| Variant | Board ID | SIM Topology | Firmware Verification | Detailed Guide |
| :--- | :---: | :--- | :--- | :--- |
| **F50 Pro 插卡版** (Physical SIM + eSIM) | `board_id=6` (`B28`) | Physical Nano-SIM (`psim_select`) + internal eSIM (`chip_select`) via `u30pro_sim_mux.layout=mu3356` | Dynamic signature scan (`trustos_a` + `vendor_boot_a` DTB) | [docs/variant-psim-b28.md](docs/variant-psim-b28.md) |
| **F50 Pro 内置双 eSIM 版** (Built-in Dual eSIM) | `board_id=1` (`B15`) | Fixed internal CM/CT eSIM channels (`is_support_psim=0`) | Dynamic signature scan (`trustos_a` + `vendor_boot_a` DTB) | [docs/variant-esim-b15.md](docs/variant-esim-b15.md) |

> Hardware identity note: Both versions are ZTE `MU3356` (`UMS9632`, Android 15). Upstream generic builds may display `U30Pro` in unconfigured defaults because the shared `mu300` platform driver supports the Unisoc 5G pocket-router family; this kit sets `F50Pro-OpenWrt` SSID and `f50pro` board detection automatically.

---

## Verification & Release Readiness Status (Honest Scope: 4 Tiers Separated)

> **Important integrity notice**: [assets/release-manifest.json](assets/release-manifest.json) verifies **SHA-256 file integrity** against this repository's manifest, **not** cryptographic publisher signatures (GPG / Cosign / GitHub Attestation). For reproducible flashing, clone an **explicit Release tag or commit SHA** (latest stable tag: **`v1.1.2`** on `main`; `v1.1.0` binary packs remain frozen and intact).

| Scope | Compilation / Packaging | Host CLI / Unit & Fault Tests | Live USB Comm | End-to-End Hardware | Notes / Explicit Limits |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Pure-Python builder & safety guards (`v1.1.2`)** | `PASS` | `PASS` (`70+` pytest fault + audit + unit tests) | `N/A` *(offline)* | `N/A` *(offline)* | Offline `plan` / `auto` dry-run perform zero downloads, zero WebUI reboots, zero BROM/SSH/ADB calls; `auto --execute` uses single-session `SPRD4` (backup->build->flash with zero mid-flow reboot) + WebUI/OpenWrt-SSH/ADB auto-reboot; includes multi-agent audit fixes, `apk-tools 3.0.5` fix, Wi-Fi repeater fixes, and `--force --all` Windows WinUSB pre-installer. |
| **Windows x64 host toolkit (`v1.1.0` + P0)** | `PASS` | `PASS` (`win32` + CI `windows-latest`) | `PASS` *(upstream WinUSB)* | **`B28` VERIFIED *(upstream)*** / `UNVERIFIED` *(this CLI)* | Upstream `B28` verified full `_a`+`_b`+`5G NR SA`+Wi-Fi 6+OpenClash+5s roundtrip; refactored `kit.py` CLI awaiting authorized pilot. |
| **`B15` (`board_id=1`, Built-in Dual eSIM)** | `PASS` *(image build parity)* | `PASS` *(DTB & offset fixture)* | `PASS` *(upstream dump)* | `PARTIAL` *(dual-boot roundtrip verified upstream)* | Upstream installed & roundtrip-switched `_b <-> _a`; **paid eSIM cellular WAN intentionally NOT tested per user decision (non-blocker)**. |
| **Linux `x86_64` host** | `PASS` | `PASS` (CI `ubuntu-latest`) | `UNVERIFIED` *(live USB)* | `UNVERIFIED` | CI verifies `bootstrap.sh`, `preflight --strict`, offline `plan`, `spd_dump -h`, and `adb version`; physical USB flash/NCM isolation awaits live run. |
| **macOS Universal (`arm64` + `x86_64`)** | `PASS` (`Mach-O` + CI `macos-latest`) | `PASS` (CI `macos-latest`) | `UNVERIFIED` *(live USB)* | `UNVERIFIED` | Requires `sudo` / `--spd-mode sudo` for raw `libusb`; `Hardware Port` / `Device` / `Network Service` correlation covered by unit tests. |
| **Linux `aarch64` (`arm64`) host** | `PASS` (`musl` binary) | **`NOT CI-TESTED`** *(unit parsers only)* | `UNVERIFIED` | `UNVERIFIED` | No native `ubuntu-arm64` runner in CI matrix; relies on distro `android-tools-adb`. |
| **Android Termux OTG (`arm64`)** | `PASS` (`spd_dump-su`, `spd_dump-termux-usb`) | `PARTIAL` *(CLI argv tests only)* | `UNVERIFIED` | `UNVERIFIED` | **Root (`--spd-mode su`)**: full `--kickto 2`. **Non-Root (`--usb-fd`)**: single-grant FD does not survive reset/re-enumeration (`EXPERIMENTAL`, not turnkey closed-loop). |
| **`SPRD4:AutoD` vs Bare-Metal `SPRD3` unbrick** | `N/A` | `PASS` *(guard test)* | `VERIFIED` *(upstream `AutoD`)* | **`BLOCKED` on `SPL`/`U-Boot` loss** | Requires intact **`SPL + U-Boot` (`autodloader`)**; bundles **no** signed `UMS9632` `FDL1`/`FDL2` (`0x65008000`/`0xbdfffe00`) or `.pac`; `r all` omits `splloader_bak`. |

See [docs/P0_REMEDIATION_REPORT_v1.1.1-rc.1.md](docs/P0_REMEDIATION_REPORT_v1.1.1-rc.1.md) and [docs/RELEASE_QUALITY_AUDIT_v1.0.0.md](docs/RELEASE_QUALITY_AUDIT_v1.0.0.md).

---

## Three Flash Profiles

| Profile ID | Android Slot `_a` | OpenWrt Slot `_b` (`25.12.5`) | Switching & Highlights |
| :--- | :--- | :--- | :--- |
| **`1-android-ufi`** | Rooted (`Magisk 28103`) + **UFI-TOOLS** (`:2333`, `ttyd` `:1146`) | Untouched | Single-slot root + advanced management console |
| **`2-dual-stock-openwrt`** | **100% Untouched Stock Android** | OpenWrt `25.12.5` (`Linux 6.12.94`, `2 GiB` rootfs on `fulldumpdb`, capacity UI, Wi-Fi LED fix, concurrent AP+STA Wi-Fi Repeater UI w/ 25s fail-safe AP fallback, `rndis+acm`, optional OpenClash) | Zero risk to stock Android; 5s physical key switches `OpenWrt -> Android` |
| **`3-dual-full`** | Rooted (`Magisk 28103`) + **UFI-TOOLS** + USB `charging,adb` isolation | Full OpenWrt `25.12.5` (`2 GiB`, capacity UI, Wi-Fi LED fix, concurrent AP+STA Wi-Fi Repeater UI w/ 25s fail-safe AP fallback, `rndis+acm`, optional OpenClash) | **Bidirectional 5s physical button switching (`OpenWrt <-> Android`)** + Windows host RNDIS gateway isolation |

See [docs/profiles.md](docs/profiles.md) for full details and flag customization.

---

## Supported Host OSes & Selectable Downloads (`v1.1.0`)

Pick only the host tool bundle + firmware/APK packs you actually need (via interactive menu, CLI filters, or manual download from Release `v1.1.0`):

### Quick Bootstrap per Host Platform

| Host Device | Bootstrap Command | USB / Privilege Notes | Detailed Guide |
| :--- | :--- | :--- | :--- |
| **Windows x64** | `.\scripts\bootstrap.ps1` (add `-Interactive`, `-Profile`, `-SkipOpenClash`) | Run `.\scripts\install_unisoc_drivers.bat` (Admin, uses `--force --all` for offline `1782:4D00`/`4D03` pre-install) + RNDIS6 isolator | Steps below |
| **Linux (`x86_64` / `arm64`)** | `bash scripts/bootstrap.sh` (add `--interactive`, `--profile`, `--no-openclash`) | Install `assets/udev/99-unisoc-f50pro.rules` or pass `--spd-mode sudo`; ARM64 needs distro `android-tools-adb` | [docs/multi-platform-host.md](docs/multi-platform-host.md) |
| **macOS (Apple Silicon / Intel)** | `bash scripts/bootstrap.sh --platform macos` | Universal Mach-O binaries; raw USB requires `sudo` (`--spd-mode sudo`) + `networksetup` isolation | [docs/multi-platform-host.md](docs/multi-platform-host.md) |
| **Android OTG (Termux `arm64`)** | `bash scripts/bootstrap.sh --platform android-arm64` | **Rooted (`su`)**: full `--spd-mode su` (`--kickto 2`). **Non-Root**: `--spd-mode termux-usb` (`--usb-fd`, pre-entered `1782:4d00` only) + wireless ADB / `termux-adb` | [docs/multi-platform-host.md](docs/multi-platform-host.md) |

### Selectable Release Packs (`v1.1.0`)

List packs + direct URLs without downloading: `python3 scripts/kit.py fetch-assets --list-packs`

| Pack Key | Release Archive | Size | Needed By | SHA-256 (first 12) |
| :--- | :--- | :---: | :--- | :--- |
| `host_tools_win64` | `f50pro-host-tools-win64.zip` | 25.61 MiB | Windows x64 hosts | `ebcdb45807eb` |
| `host_tools_linux_x64` | `f50pro-host-tools-linux-x64.tar.gz` | 6.33 MiB | Linux `x86_64` hosts | `191f86bb8784` |
| `host_tools_linux_arm64` | `f50pro-host-tools-linux-arm64.tar.gz` | 0.75 MiB | Linux `aarch64` hosts | `61af85e98990` |
| `host_tools_macos` | `f50pro-host-tools-macos-universal.tar.gz` | 11.18 MiB | macOS M1–M4 & Intel hosts | `f7cfe8a5dc02` |
| `host_tools_android_arm64` | `f50pro-host-tools-android-arm64.tar.gz` | 1.30 MiB | Android Termux OTG hosts | `b3a8ae891a73` |
| `openwrt_base` | `f50pro-base-openwrt-25.12.5-pack.tar.xz` | 24.86 MiB | Profiles `2`, `3` | `ebd302a22b35` |
| `android_pkgs` | `f50pro-android-pkgs-pack.zip` | 30.29 MiB | Profiles `1`, `3` | `242f09e3911f` |
| `openclash_offline` | `f50pro-openclash-offline-25.12.5-arm64.tar.gz` | 35.78 MiB | Optional (`--openclash`) | `c1b0a739aafe` |

---

## One-Click Deployment

### 1. Pinned Clone, Python `.venv`, Dependencies & Selected Packs

```powershell
# Windows: pin explicit release tag v1.1.2 (or latest main); v1.1.0 binary packs remain frozen
git clone --branch v1.1.2 --depth 1 https://github.com/tanjiu90/f50pro-dualboot-kit.git
cd f50pro-dualboot-kit
.\scripts\bootstrap.ps1
# First time on Windows (Run PowerShell as Administrator): pre-install Unisoc BROM/Boot Diag WinUSB drivers
.\scripts\install_unisoc_drivers.bat
```

```bash
# Linux / macOS / Android Termux: pin tag v1.1.2, then auto-detect OS/arch or pass --interactive / --profile
git clone --branch v1.1.2 --depth 1 https://github.com/tanjiu90/f50pro-dualboot-kit.git
cd f50pro-dualboot-kit
bash scripts/bootstrap.sh --interactive
```

This creates `.venv`, installs `paramiko`, `pyserial`, and `pytest`, downloads & SHA-256-verifies your chosen Release packs against [assets/release-manifest.json](assets/release-manifest.json) *(integrity checksum only; not a cryptographic signature)*, and generates your local `~/.android/adbkey.pub` if absent.

### 2. Strict Preflight, Read-Only Probe, Explicit Backup & Offline Plan Boundaries

```bash
# 1. Host tools + modules strict preflight (zero device contact; exits non-zero if missing)
.venv/bin/python scripts/kit.py preflight --strict --operation backup

# 2. Read-only non-reboot online probe (SSH/ADB/LuCI/route audit; never triggers REBOOT_DEVICE)
.venv/bin/python scripts/kit.py probe --profile 3-dual-full --root-password "<PW>"

# 3. Capture BROM backup (requires explicit --authorize-device-reboot because AutoD resets device)
.venv/bin/python scripts/kit.py backup --output-dir build/my-device/backup --authorize-device-reboot --webui-password "<YOUR_WEBUI_PASSWORD>"

# 4. 100% Offline Plan & Dry-Run (ZERO HTTP downloads, ZERO WebUI reboot, ZERO flash/NIC writes)
.venv/bin/python scripts/kit.py plan --profile 3-dual-full --work-dir build/my-device --openclash
# (Equivalent: running `kit.py auto --profile 3-dual-full --work-dir build/my-device` without `--execute`)

# 5. Single-session zero-replug execution: captures backup, derives images, flashes & readback-verifies inside ONE SPRD4 session (WebUI / OpenWrt SSH / ADB auto-reboot; pass --reuse-backup only to skip BROM backup):
.\.venv\Scripts\python.exe scripts\kit.py auto \
  --profile 3-dual-full \
  --work-dir build/my-device \
  --webui-password "<YOUR_WEBUI_PASSWORD>" \
  --generate-password \
  --openclash \
  --execute
```

> On macOS (or Linux without `udev` rules), pass `--spd-mode sudo` (use `assets/udev/99-unisoc-f50pro.rules` on Linux for non-root USB access instead of running Python as root). By default `provision-openwrt` preserves working USB modes (`ncm`/`ecm`/`rndis`) while recovering Win10 CDC-NCM driver failures over the `MI_02` serial console automatically, and uses `Asia/Shanghai` / `CST-8` unless `--zonename` / `--timezone` are customized; pass `--usb-net-mode rndis` (and optional `--usb-net-persist`) only when needed. On Rooted Android Termux pass `--spd-mode su`. Use `--profile 1-android-ufi` or `--profile 2-dual-stock-openwrt` to deploy the other two configurations (`fetch-assets --profile ...` skips unneeded bundles).

---

## Repair a legacy F50 Pro USB boot hang

Older OpenWrt installations with `/etc/init.d/f50pro-usb` can hang during boot when the script removes an ACM serial function held open by the login console. Services later in the boot order, including OpenClash, then remain offline. The [legacy USB boot repair](assets/openwrt-patch/f50pro-legacy-usb-boot-fix.sh) moves the RNDIS default to early initialization and preserves saved USB-mode policies.

With a verified device backup, save `/etc/init.d/f50pro-usb` and `/usr/sbin/u30pro-usb-boot` for rollback. Copy the repair script to `/tmp` and run `sh /tmp/f50pro-legacy-usb-boot-fix.sh` as root over SSH. Reboot OpenWrt to apply the repair and verify the USB profile and affected services. The v1.1.1 base image uses a different startup sequence.

## AI Agent One-Line Turnkey Prompt

Hand your AI coding Agent (Antigravity, Claude Code, Codex CLI, Cursor, etc.) the repository URL and instruct it to follow [AGENT-FLASH.md](AGENT-FLASH.md):

```text
Clone https://github.com/tanjiu90/f50pro-dualboot-kit and follow AGENT-FLASH.md strictly.
Run preflight + bootstrap + full BROM backup + inspect first, then build Profile <1-android-ufi | 2-dual-stock-openwrt | 3-dual-full>, stop at the dry-run gate for my confirmation before passing --execute, provision, and output the verified E2E report.
```

---

## Architecture, Safety & Cleanliness Guarantees

1. **Zero WSL Dependency**: Both Magisk `init_boot_a` packing (`CRC32` XZ + LZ4 legacy + AVB footer relocation) and own-device `trustos` derivation run in pure Python on Windows.
2. **Per-Device Cryptographic Derivation**: Never flashes foreign bootloader binaries or generic `trustos` dumps; `trustos_noavb.img` is derived dynamically from the target device's own `sml_a` + `trustos_a` backup, and `vendor_boot_b` keeps the target device's exact stock DTB SHA-256.
3. **Immutable Factory Calibration & Target Identity Guards**: `FORBIDDEN_PARTITIONS` + per-profile operation allowlists block writes outside approved partitions/ranges, and `flash_plan.json` binds via cryptographic SHA-256 digest of immutable, non-zero per-unit factory partitions (`ztecfg`/`persist`) + GPT layout to prevent cross-unit mixups without false positives across OS reboots (never matching on generic USB VID/PID alone).
4. **Scoped Host Network Isolation & Clean Failure Recovery**: `host_network.py` matches only verified F50 Pro USB interfaces (`1D6B:0104`, never phone USB tethering or USB-C docks), skips normal Wi-Fi gateways (`192.168.0.1`), saves/restores snapshots without clobbering manual configs, and `flash_images.py` stops on write/readback/GPT failure without auto-rebooting or switching slots (`flash_state.json`).
5. **Clean Configs & Prebuilt Binary Scope**: Optional OpenClash pack contains only signed `.apk`s, `mihomo`, GeoIP databases, and a neutral `proxies: []` [template.yaml](assets/openwrt-patch/openclash-clean/template.yaml) with **zero personal subscriptions or proxy nodes**. Release `v1.0.0` `openwrt-base` rootfs bundles prebuilt `aic8800` Wi-Fi firmware / modem XMLs from reference `B28` extracts and `android-pkgs` bundles upstream `UFI-TOOLS.apk` (see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)); Git commits contain zero binary images, IMEIs, NV data, passwords, or device backups.

---

## Documentation Index

- [docs/beginner-guide.md](docs/beginner-guide.md) — **零基础小白保姆级使用教程**（Windows 主流程 + macOS / Linux / Termux 附注 + 日常使用与救砖回退）
- [AGENT-FLASH.md](AGENT-FLASH.md) — Autonomous AI Agent SOP & safety gates
- [docs/P0_REMEDIATION_REPORT_v1.1.1-rc.1.md](docs/P0_REMEDIATION_REPORT_v1.1.1-rc.1.md) — P0-1..P0-6 safety remediation report, failure tests & `v1.1.1-rc.1` plan
- [docs/multi-platform-host.md](docs/multi-platform-host.md) — Linux, macOS, Android Termux OTG & selectable downloads guide
- [docs/variant-psim-b28.md](docs/variant-psim-b28.md) — F50 Pro 插卡版 (`board_id=6`) hardware & SIM-mux reference
- [docs/variant-esim-b15.md](docs/variant-esim-b15.md) — F50 Pro 内置双 eSIM 版 (`board_id=1`) reference
- [docs/profiles.md](docs/profiles.md) — Profile 1 / 2 / 3 deep dive & customization options
- [docs/architecture.md](docs/architecture.md) — Unisoc `MU3356` A/B layout, `DHTB`/`AVB0` internals, `BCAB` control
- [docs/recovery-and-safety.md](docs/recovery-and-safety.md) — BROM entry, WinUSB driver setup, rollback & recovery
- [docs/openclash-template-guide.md](docs/openclash-template-guide.md) — Offline OpenClash deployment & adding custom subscriptions
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) — Upstream attributions & licenses
