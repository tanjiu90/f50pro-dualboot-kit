# F50 Pro Dual-Boot Kit (`MU3356` / `UMS9632`)

Turnkey, sanitized, **pure-Python (zero-WSL)** toolkit for backing up, building, flashing, provisioning, and verifying **ZTE F50 Pro** across both hardware variants (**插卡版 `board_id=6`** and **内置双 eSIM 版 `board_id=1`**) with **3 selectable configurations** and **multi-platform host deployment (`Windows`, `Linux`, `macOS`, `Android Termux OTG`)**.

Designed for **one-click per-OS selective download & deployment** and **autonomous AI Agent flashing** (`AGENT-FLASH.md`).

---

## Supported Hardware Variants

| Variant | Board ID | SIM Topology | Firmware Verification | Detailed Guide |
| :--- | :---: | :--- | :--- | :--- |
| **F50 Pro 插卡版** (Physical SIM + eSIM) | `board_id=6` (`B28`) | Physical Nano-SIM (`psim_select`) + internal eSIM (`chip_select`) via `u30pro_sim_mux.layout=mu3356` | Dynamic signature scan (`trustos_a` + `vendor_boot_a` DTB) | [docs/variant-psim-b28.md](docs/variant-psim-b28.md) |
| **F50 Pro 内置双 eSIM 版** (Built-in Dual eSIM) | `board_id=1` (`B15`) | Fixed internal CM/CT eSIM channels (`is_support_psim=0`) | Dynamic signature scan (`trustos_a` + `vendor_boot_a` DTB) | [docs/variant-esim-b15.md](docs/variant-esim-b15.md) |

> Hardware identity note: Both versions are ZTE `MU3356` (`UMS9632`, Android 15). Upstream generic builds may display `U30Pro` in unconfigured defaults because the shared `mu300` platform driver supports the Unisoc 5G pocket-router family; this kit sets `F50Pro-OpenWrt` SSID and `f50pro` board detection automatically.

---

## Verification & Release Readiness Status (Honest Scope)

| Scope | Status | Evidence / Limits |
| :--- | :---: | :--- |
| **Offline Python builder, safety guards & clean-room HTTPS bootstrap** | `VERIFIED` | Tested in fresh `.venv` (`46` `pytest` cases) + GitHub Actions multi-OS CI (`ubuntu-latest`, `macos-latest`, `windows-latest`) + read-only binary parity against `B15` stock backup. |
| **Linux / macOS / Android Termux OTG host flashing (`v1.1.0`)** | `CI-VERIFIED` *(host CLI)* / `UNVERIFIED` *(live USB)* | Host binaries verified (`musl` v251 ELFs, `Universal Mach-O` `spd_dump`, Android NDK `spd_dump-termux-usb`, Google `platform-tools 37.0.1`), Linux/macOS CLI/route-parser unit-tested + CI tested. Live F50 Pro USB flashing from Linux/macOS/Android hosts has **not** yet been run on physical hardware; Non-root Android `--usb-fd` cannot auto-run `--kickto 2` reconnect (`EXPERIMENTAL`). |
| **`B28` (`board_id=6`, Physical SIM) dual-boot architecture** | `VERIFIED` *(upstream)* / `UNVERIFIED` *(this CLI)* | Upstream predecessor project verified full `_a` + `_b` + `5G NR SA` + Wi-Fi 6 + OpenClash + physical `5s` button roundtrip on hardware. Refactored `kit.py` CLI has **not** yet been run end-to-end on physical hardware. |
| **`B15` (`board_id=1`, Built-in Dual eSIM) dual-boot architecture** | `PARTIAL` *(upstream)* / `UNVERIFIED` *(this CLI)* | Upstream predecessor project flashed `_b` + Android `_a` Magisk + `UFI-TOOLS` + bidirectional roundtrip on `B15` (`final-roundtrip-verify.json`); however, OpenWrt cellular WAN remained disconnected during that snapshot (`wan.up=0`, `net_red=1`) and used a `B28`-built stage3 rootfs. |
| **Profile `1-android-ufi` & `2-dual-stock-openwrt` isolated runs** | `UNVERIFIED` *(live)* | Plan builders, safety guardrails, and offline output verified via synthetic fixtures; not yet separately flashed end-to-end via `kit.py`. |
| **`SPRD4:AutoD` backup & partition write/readback** | `VERIFIED` *(upstream)* | Requires healthy on-device **`SPL + U-Boot` (`autodloader`)**. Does **not** capture `splloader_bak` (`eMMC boot1`). |
| **Bare-metal `SPRD3` BootROM unbrick when `SPL` / `U-Boot` fails** | `BLOCKED` / `NOT INCLUDED` | If active `uboot` or `splloader` fails verification (`SPL 0x4e` halt without auto-fallback), `SPRD4:AutoD` disappears; this kit bundles **no** signed `UMS9632` `FDL1`/`FDL2` (`0x65008000`/`0xbdfffe00`) and **no** factory `.pac`. |

See the full [Release Quality Audit Report](docs/RELEASE_QUALITY_AUDIT_v1.0.0.md).

---

## Three Flash Profiles

| Profile ID | Android Slot `_a` | OpenWrt Slot `_b` (`25.12.5`) | Switching & Highlights |
| :--- | :--- | :--- | :--- |
| **`1-android-ufi`** | Rooted (`Magisk 28103`) + **UFI-TOOLS** (`:2333`, `ttyd` `:1146`) | Untouched | Single-slot root + advanced management console |
| **`2-dual-stock-openwrt`** | **100% Untouched Stock Android** | OpenWrt `25.12.5` (`Linux 6.12.94`, `2 GiB` rootfs on `fulldumpdb`, capacity UI, Wi-Fi LED fix, `rndis+acm`, optional OpenClash) | Zero risk to stock Android; 5s physical key switches `OpenWrt -> Android` |
| **`3-dual-full`** | Rooted (`Magisk 28103`) + **UFI-TOOLS** + USB `charging,adb` isolation | Full OpenWrt `25.12.5` (`2 GiB`, capacity UI, Wi-Fi LED fix, `rndis+acm`, optional OpenClash) | **Bidirectional 5s physical button switching (`OpenWrt <-> Android`)** + Windows host RNDIS gateway isolation |

See [docs/profiles.md](docs/profiles.md) for full details and flag customization.

---

## Supported Host OSes & Selectable Downloads (`v1.1.0`)

Pick only the host tool bundle + firmware/APK packs you actually need (via interactive menu, CLI filters, or manual download from Release `v1.1.0`):

### Quick Bootstrap per Host Platform

| Host Device | Bootstrap Command | USB / Privilege Notes | Detailed Guide |
| :--- | :--- | :--- | :--- |
| **Windows x64** | `.\scripts\bootstrap.ps1` (add `-Interactive`, `-Profile`, `-SkipOpenClash`) | Includes fixed `install_connected_drivers.bat` -> `unisoc_drivers.txt` + RNDIS6 isolator | Steps below |
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

### 1. Bootstrap Python `.venv`, Dependencies & Selected Packs

```powershell
# Windows: auto-selects host_tools_win64 (use -Interactive to customize packs)
git clone https://github.com/tanjiu90/f50pro-dualboot-kit.git
cd f50pro-dualboot-kit
.\scripts\bootstrap.ps1
```

```bash
# Linux / macOS / Android Termux: auto-detects OS/arch, or pass --interactive / --platform / --profile
git clone https://github.com/tanjiu90/f50pro-dualboot-kit.git
cd f50pro-dualboot-kit
bash scripts/bootstrap.sh --interactive
```

This creates `.venv`, installs `paramiko`, `pyserial`, and `pytest`, downloads & SHA-256-verifies your chosen `v1.1.0` packs against [assets/release-manifest.json](assets/release-manifest.json), and generates your local `~/.android/adbkey.pub` if absent.

### 2. Preflight & Turnkey Workflow

```bash
# Check tools, Python modules, ADB pubkey, and host routes (read-only)
.venv/bin/python scripts/kit.py preflight   # Windows: .\.venv\Scripts\python.exe scripts\kit.py preflight

# Safe dry-run up through BROM backup, variant inspection, image build, and flash_plan.json
.venv/bin/python scripts/kit.py auto \
  --profile 3-dual-full \
  --work-dir build/my-device \
  --webui-password "<YOUR_WEBUI_PASSWORD>" \
  --generate-password \
  --openclash

# Review build/my-device/build/flash_plan.json, then execute flash + provision + E2E verify:
.venv/bin/python scripts/kit.py auto \
  --profile 3-dual-full \
  --work-dir build/my-device \
  --reuse-backup \
  --webui-password "<YOUR_WEBUI_PASSWORD>" \
  --generate-password \
  --openclash \
  --execute
```

> On macOS (or Linux without udev rules), pass `--spd-mode sudo` or run `sudo .venv/bin/python ...`. On Rooted Android Termux pass `--spd-mode su`. Use `--profile 1-android-ufi` or `--profile 2-dual-stock-openwrt` to deploy the other two configurations (and `fetch-assets --profile ...` automatically skips unneeded bundles!).

---

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
3. **Immutable Factory Calibration Guards**: `FORBIDDEN_PARTITIONS` blocks writes to `splloader`, `prodnv`, `calinv`, `ztecfg`, `ztepersist`, `persist`, `miscdata`, `super`, `userdata`, and modem NV/calibration partitions.
4. **Windows Host Cellular Hijack Prevention**: `host_network.py` isolates both `UsbNcm` (initial boot default of base ext4 rootfs) and `RNDIS` (`1D6B:0104`) interfaces to static `192.168.77.12/24`, strips default gateways/DNS/IPv6, and audits the Windows routing table so your host PC stays connected via its primary internet adapter.
5. **Clean Configs & Prebuilt Binary Scope**: Optional OpenClash pack contains only signed `.apk`s, `mihomo`, GeoIP databases, and a neutral `proxies: []` [template.yaml](assets/openwrt-patch/openclash-clean/template.yaml) with **zero personal subscriptions or proxy nodes**. Release `v1.0.0` `openwrt-base` rootfs bundles prebuilt `aic8800` Wi-Fi firmware / modem XMLs from reference `B28` extracts and `android-pkgs` bundles upstream `UFI-TOOLS.apk` (see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)); Git commits contain zero binary images, IMEIs, NV data, passwords, or device backups.

---

## Documentation Index

- [AGENT-FLASH.md](AGENT-FLASH.md) — Autonomous AI Agent SOP & safety gates
- [docs/multi-platform-host.md](docs/multi-platform-host.md) — Linux, macOS, Android Termux OTG & selectable downloads guide
- [docs/variant-psim-b28.md](docs/variant-psim-b28.md) — F50 Pro 插卡版 (`board_id=6`) hardware & SIM-mux reference
- [docs/variant-esim-b15.md](docs/variant-esim-b15.md) — F50 Pro 内置双 eSIM 版 (`board_id=1`) reference
- [docs/profiles.md](docs/profiles.md) — Profile 1 / 2 / 3 deep dive & customization options
- [docs/architecture.md](docs/architecture.md) — Unisoc `MU3356` A/B layout, `DHTB`/`AVB0` internals, `BCAB` control
- [docs/recovery-and-safety.md](docs/recovery-and-safety.md) — BROM entry, WinUSB driver setup, rollback & recovery
- [docs/openclash-template-guide.md](docs/openclash-template-guide.md) — Offline OpenClash deployment & adding custom subscriptions
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) — Upstream attributions & licenses
