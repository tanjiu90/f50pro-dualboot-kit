# F50 Pro Dual-Boot Kit (`MU3356` / `UMS9632`)

Turnkey, sanitized, **pure-Python (zero-WSL)** toolkit for backing up, building, flashing, provisioning, and verifying **ZTE F50 Pro** across both hardware variants (**插卡版 `board_id=6`** and **内置双 eSIM 版 `board_id=1`**) with **3 selectable configurations**.

Designed for **one-click Windows deployment** and **autonomous AI Agent flashing** (`AGENT-FLASH.md`).

---

## Supported Hardware Variants

| Variant | Board ID | SIM Topology | Firmware Verification | Detailed Guide |
| :--- | :---: | :--- | :--- | :--- |
| **F50 Pro 插卡版** (Physical SIM + eSIM) | `board_id=6` (`B28`) | Physical Nano-SIM (`psim_select`) + internal eSIM (`chip_select`) via `u30pro_sim_mux.layout=mu3356` | Dynamic signature scan (`trustos_a` + `vendor_boot_a` DTB) | [docs/variant-psim-b28.md](docs/variant-psim-b28.md) |
| **F50 Pro 内置双 eSIM 版** (Built-in Dual eSIM) | `board_id=1` (`B15`) | Fixed internal CM/CT eSIM channels (`is_support_psim=0`) | Dynamic signature scan (`trustos_a` + `vendor_boot_a` DTB) | [docs/variant-esim-b15.md](docs/variant-esim-b15.md) |

> Hardware identity note: Both versions are ZTE `MU3356` (`UMS9632`, Android 15). Upstream generic builds may display `U30Pro` in unconfigured defaults because the shared `mu300` platform driver supports the Unisoc 5G pocket-router family; this kit sets `F50Pro-OpenWrt` SSID and `f50pro` board detection automatically.

---

## Three Flash Profiles

| Profile ID | Android Slot `_a` | OpenWrt Slot `_b` (`25.12.5`) | Switching & Highlights |
| :--- | :--- | :--- | :--- |
| **`1-android-ufi`** | Rooted (`Magisk 28103`) + **UFI-TOOLS** (`:2333`, `ttyd` `:1146`) | Untouched | Single-slot root + advanced management console |
| **`2-dual-stock-openwrt`** | **100% Untouched Stock Android** | OpenWrt `25.12.5` (`Linux 6.12.94`, `2 GiB` rootfs on `fulldumpdb`, capacity UI, Wi-Fi LED fix, `rndis+acm`, optional OpenClash) | Zero risk to stock Android; 5s physical key switches `OpenWrt -> Android` |
| **`3-dual-full`** | Rooted (`Magisk 28103`) + **UFI-TOOLS** + USB `charging,adb` isolation | Full OpenWrt `25.12.5` (`2 GiB`, capacity UI, Wi-Fi LED fix, `rndis+acm`, optional OpenClash) | **Bidirectional 5s physical button switching (`OpenWrt <-> Android`)** + Windows host RNDIS gateway isolation |

See [docs/profiles.md](docs/profiles.md) for full details and flag customization.

---

## One-Click Deployment (Fresh Windows PC)

### 1. Bootstrap Python `.venv`, Dependencies & Verified Release Packs

```powershell
git clone https://github.com/tanjiu90/f50pro-dualboot-kit.git
cd f50pro-dualboot-kit
.\scripts\bootstrap.ps1
```

This creates `.venv`, installs `paramiko`, `pyserial`, and `pytest`, downloads & SHA-256-verifies Release `v1.0.0` packs against [assets/release-manifest.json](assets/release-manifest.json), and generates your local `~/.android/adbkey.pub` if absent.

### 2. Preflight & Turnkey Workflow

```powershell
# Check tools, Python modules, ADB pubkey, and Windows routes (read-only)
.\.venv\Scripts\python.exe scripts\kit.py preflight

# Safe dry-run up through BROM backup, variant inspection, image build, and flash_plan.json
.\.venv\Scripts\python.exe scripts\kit.py auto `
  --profile 3-dual-full `
  --work-dir build\my-device `
  --webui-password "<YOUR_WEBUI_PASSWORD>" `
  --generate-password `
  --openclash

# Review build\my-device\build\flash_plan.json, then execute flash + provision + E2E verify:
.\.venv\Scripts\python.exe scripts\kit.py auto `
  --profile 3-dual-full `
  --work-dir build\my-device `
  --reuse-backup `
  --webui-password "<YOUR_WEBUI_PASSWORD>" `
  --generate-password `
  --openclash `
  --execute
```

> Use `--profile 1-android-ufi` or `--profile 2-dual-stock-openwrt` in the exact same command to deploy the other two configurations.

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
4. **Windows Host Cellular Hijack Prevention**: `host_network.py` binds Microsoft's inbox `netrndis.inf` driver, assigns static `192.168.77.12/24`, strips default gateways/DNS/IPv6 from the USB RNDIS interface, and audits the Windows routing table so your host PC stays connected via its primary internet adapter.
5. **Clean OpenClash Pack**: Optional offline bundle provides only signed OpenWrt IPKs/APKs, `mihomo` binary, GeoIP databases, and a neutral fake-ip [template.yaml](assets/openwrt-patch/openclash-clean/template.yaml) with **zero personal subscriptions or proxy nodes**.

---

## Documentation Index

- [AGENT-FLASH.md](AGENT-FLASH.md) — Autonomous AI Agent SOP & safety gates
- [docs/variant-psim-b28.md](docs/variant-psim-b28.md) — F50 Pro 插卡版 (`board_id=6`) hardware & SIM-mux reference
- [docs/variant-esim-b15.md](docs/variant-esim-b15.md) — F50 Pro 内置双 eSIM 版 (`board_id=1`) reference
- [docs/profiles.md](docs/profiles.md) — Profile 1 / 2 / 3 deep dive & customization options
- [docs/architecture.md](docs/architecture.md) — Unisoc `MU3356` A/B layout, `DHTB`/`AVB0` internals, `BCAB` control
- [docs/recovery-and-safety.md](docs/recovery-and-safety.md) — BROM entry, WinUSB driver setup, rollback & recovery
- [docs/openclash-template-guide.md](docs/openclash-template-guide.md) — Offline OpenClash deployment & adding custom subscriptions
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) — Upstream attributions & licenses
