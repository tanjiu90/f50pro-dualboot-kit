# Release Quality Audit Report — `tanjiu90/f50pro-dualboot-kit` (`main` @ `aa2deb6` & Release `v1.0.0`)

**Audit Date**: 2026-11-17  
**Audit Method**: Independent non-destructive inspection of cloned GitHub repo, GitHub Release `v1.0.0` archives, ext4/initramfs internals, upstream device verification archives, clean-room Windows `.venv` execution tests, and automated safety test suite. **Zero hardware writes performed.**  
**Audit Fix Branch**: `audit/release-quality-v1`

---

## Executive Release Verdict

**`CONDITIONAL / NOT UNCONDITIONALLY READY FOR PRODUCTION FLASHING` (`PARTIAL` on `v1.0.0`, improved to `CODE & DOCS READY FOR LIVE PILOT` on `audit/release-quality-v1`)**

Why `main@aa2deb6` + Release `v1.0.0` are **not** unconditionally ready as-published without the fixes committed on `audit/release-quality-v1` and live hardware runs:
1. **`SPRD4:AutoD` vs bare-metal `SPRD3` was misrepresented** in `v1.0.0` docs (`recovery-and-safety.md` claimed "anytime lossless recovery" without `FDL1/FDL2` even if bootloader breaks — **false** when U-Boot/SPL fails to load).
2. **`B15` vs `B28` verification asymmetry**: `B15` did complete dual-boot installation & bidirectional switching upstream, **not** just source adaptation, **but** OpenWrt cellular WAN remained disconnected (`wan.up=0`, `net_red=1`) in its verification snapshot and used a `B28`-built rootfs; **additionally, the refactored `kit.py` CLI in this public repo has never been executed live on either `B28` or `B15` (`0` live runs)**.
3. **First-boot USB / provisioning defects discovered by inspecting the actual `v1.0.0` `ext4` & `qmk_driver_installer` binaries**:
   - `openwrt-f50pro-25.12.5-base-rootfs.ext4` defaults USB gadget to `ncm` (`u30pro-usb-boot` reads `/etc/unisoc-modem/usb-boot.conf`), while `v1.0.0` `host_network.py` matched only `RNDIS` and `provision_openwrt.py` wrote `u30pro.usb.mode` instead of `/usr/libexec/unisoc-modem/device-usb set-net rndis permanent 1`.
   - `provision_openwrt.py` used an unchecked `invoke_shell` + `sleep(0.8)` for `passwd root`.
   - `qmk_driver_installer\install_connected_drivers.bat` inside `v1.0.0` `f50pro-host-tools-win64.zip` invokes `drivers.txt` (keyboards, no `1782:4D00`), requiring explicit `--force unisoc_drivers.txt`.
4. **Release `v1.0.0` proprietary vendor blobs (no PII/NV leaked, but IP/clean-room caveat exists)**: `openwrt-f50pro-25.12.5-base-rootfs.ext4` bundles ZTE/AIC `aic8800` Wi-Fi chipset firmware binaries and `modem_*.xml` from `B28` `odm_a`/`vendor_a`, and `android-pkgs` bundles `UFI-TOOLS.apk`. Zero IMEI/SN/NV/passwords/keys/personal subscriptions were leaked.

---

## Detailed Findings Across All 10 Audit Checks

### 1. Does the public repo genuinely implement all README features? — `PARTIAL`
- **Offline builder (`build_images.py` / `common.py` / `inspect_backup.py`)**: `VERIFIED` offline via 38 pytest cases + bit-exact comparison against `B15` stage3 (`trustos_noavb.img`, `boot_b`, `vendor_boot_b`).
- **Defects found in `main@aa2deb6` live provisioning scripts (fixed on `audit/release-quality-v1`)**:
  - `provision_openwrt.py` omitted persistent `/usr/libexec/unisoc-modem/device-usb set-net rndis permanent 1`, `at_port='/dev/stty_nr2'`, `sim_slots='2'`, `platform_defaults='u30pro'`, and deterministic exit-code checking for `passwd root`.
  - `host_network.py` only isolated `RNDIS` and missed initial boot `Microsoft UsbNcm` (`1D6B:0104`).
  - `provision_android.py` compared full `/dev/block/by-name/<part>` hash rather than `head -c <size_bytes>`.
- **Live execution gap**: `kit.py` itself (`backup`, `flash`, `provision-openwrt`, `provision-android`, `verify`, `auto`) has **not** been run end-to-end against hardware (`UNVERIFIED` live).

### 2. Independent Real-Device Verification Evidence: `B28` (pSIM) vs `B15` (Dual eSIM)
| Feature / Dimension | `B28` (`board_id=6`) | `B15` (`board_id=1`) | Evidence Source & Honest Rating |
| :--- | :---: | :---: | :--- |
| Upstream `SPRD4:AutoD` backup & readback verify | `VERIFIED` (82 files, `7,005,873,833` B) | `VERIFIED` (`partition_list` + dump) | Upstream `backups/...`, `flash_result.json` |
| Upstream OpenWrt `_b` flash & cold boot (`6.12.94`) | `VERIFIED` | `VERIFIED` | Upstream `codex-native-b28/`, `b15-.../final-roundtrip-verify.json` |
| Upstream `5G NR SA` cellular data on OpenWrt | `VERIFIED` (`CT 46011`, IPv4+IPv6 ping `0%` loss) | **`PARTIAL` / `UNVERIFIED` online** (`wan.up=0`, `net_red=1` in snapshot) | `runtime-verification/`, `b15-.../final-roundtrip-verify.json` |
| Upstream Wi-Fi 6 (`phy0-ap0`) + LED fix + 2 GiB expand + 5s key | `VERIFIED` | `VERIFIED` (`wifi.up=1`, `phy0-ap0`, `1.9G`, `system-switch`) | `final-roundtrip-verify.json` |
| Upstream Android `_a` Magisk `28103` + `UFI-TOOLS` (`:2333`/`:1146`) | `VERIFIED` (3x cold reboots, `charging,adb`) | `VERIFIED` (`android-boot-verify.json`, `:2333`, `:1146`, `charging,adb`) | `android-boot3-verify.json`, `b15-.../android-boot-verify.json` |
| Bidirectional `_a <-> _b` physical roundtrip switch | `VERIFIED` | `VERIFIED` (`mu300-keys -l 5000`, roundtrip OK) | `return-b-adb`, `final-roundtrip-verify.json` |
| Public `f50pro-dualboot-kit` `kit.py` CLI live run (Profiles 1/2/3) | **`UNVERIFIED`** | **`UNVERIFIED`** | Repo created cleanly without re-flashing live devices |

### 3. `B15` Status: Source Adaptation Only vs Dual-Boot Actually Installed & Verified?
- **Conclusion (`PARTIAL`)**: Upstream (`zte-f50pro-openwrt/build/b15-<device>-audit/`) **did physically install and verify dual-boot on `B15` (`board_id=1`)**, including readback-verified `_b` flash, `Magisk 28103` + `UFI-TOOLS v4.0.0` on `_a`, `charging,adb`, and `_b <-> _a <-> _b` roundtrip switching with `mu300-keys -l 5000`.
- **What remains unverified on `B15`**: (a) `final-roundtrip-verify.json` recorded `wan.up=0`, `ip4=null`, `net_red=1`, `imeis=[null, null]` (eSIM mobile data connectivity in OpenWrt is **not** confirmed online); (b) `B15` OpenWrt rootfs used the `B28`-extracted stage3 rootfs image; (c) the new `f50pro-dualboot-kit` `kit.py` scripts have not been run live on `B15`.

### 4 & 5. `SPRD4:AutoD` vs Bare-Metal `SPRD3`, and Recovery When `U-Boot` Cannot Load
- **Audit verdict on `v1.0.0` docs**: `main@aa2deb6` `docs/recovery-and-safety.md` conflated `SPRD4:AutoD` with universal bare-metal BROM recovery and falsely claimed "anytime lossless recovery" without `FDL1/FDL2`.
- **Technical reality (`VERIFIED` via upstream `splloader` disassembly & `spd_dump.c`)**:
  - `SPRD4:AutoD` runs inside **intact flash `SPL + U-Boot` (`autodloader`)**. `spd_dump.c` lines `473/477/818/826` automatically skip external `exec_addr`/`fdl1`/`fdl2` when `BSL_REP_VER == "SPRD4:AutoD"`. Historical upstream logs succeeded `8/8` times only via `SPRD4:AutoD` and **`0/18` times via `SPRD3`**.
  - **When `U-Boot` cannot load** (e.g., damaged `splloader` or corrupted active `uboot_<slot>`): `splloader` checks ONLY the single active slot in `misc` and halts at error `0x4e` (`0x0ab28` dead loop) with **no automatic fallback to the opposite slot's `uboot`**. `AutoD` becomes unreachable, and `spd_dump --kickto 2` **cannot recover the device** because no signed `UMS9632` `FDL1` (`0x65008000`) + `FDL2` (`0xbdfffe00`) or `.pac` is bundled in this repository (`BLOCKED` without external signed FDL).
  - Additionally, `spd_dump r all` captures `splloader` (`eMMC boot0`) but omits `splloader_bak` (`eMMC boot1`).
- **Remediations on `audit/release-quality-v1`**: Updated `brom_backup.py` (`bare_metal_sprd3_ready=False`, `splloader_bak` warning), `flash_images.py`, `README.md`, `AGENT-FLASH.md`, and `docs/recovery-and-safety.md`.

### 6 & 7. Release `v1.0.0`, Manifest SHA-256, `bootstrap.ps1` & Fresh Clean-Room Windows Verification
- **Clean-room clone verification (`VERIFIED`)**: Shallow-cloned `https://github.com/tanjiu90/f50pro-dualboot-kit.git` into an isolated empty folder (`no dist/`), executed `scripts\bootstrap.ps1` on Windows `.venv` (Python `3.11.9`):
  - Downloaded all 4 `v1.0.0` packs over GitHub HTTPS;
  - Verified exact byte sizes and SHA-256 checksums matching `assets/release-manifest.json` (`openwrt_base`, `android_pkgs` + nested APKs, `host_tools_win64`, `openclash_offline`);
  - Resolved `spd_dump.exe` (`libusb-1.0.dll` bundled alongside it) and `adb.exe` (`AdbWinApi.dll`, `AdbWinUsbApi.dll` bundled alongside it), executed `kit.py preflight` cleanly (`usb_default_route_leak: false`).
- **Defect in `v1.0.0` `f50pro-host-tools-win64.zip` (`PARTIAL`)**: `qmk_driver_installer\install_connected_drivers.bat` references keyboard `drivers.txt` instead of `unisoc_drivers.txt`. Documented explicit `--force unisoc_drivers.txt` CLI workaround on `audit/release-quality-v1`; asset rebuild deferred to `v1.0.1`.

### 8. Sensitive Data, Proprietary Images, IMEI, NV, Keys & Credentials Scan (`VERIFIED` zero PII; `PARTIAL` proprietary blobs in `v1.0.0`)
- **Git repository (`main` & `audit/release-quality-v1`)**: `0` factory partition images, `0` IMEIs/SNs/ICCIDs, `0` NV calibration (`prodnv`/`nr_*nv*`), `0` private keys, `0` personal passwords/OpenClash subscriptions (`test_sanitization.py` enforced).
- **Release `v1.0.0` packs**:
  - Deep ext4 extraction + regex scan confirmed **0** PII/IMEI/NV/SSH host keys/personal Wi-Fi/clash configs (`etc/dropbear` empty, `etc/shadow` generic `"root"` build hash `$6$u30pro$...`).
  - **`openwrt-f50pro-25.12.5-base-rootfs.ext4`** DOES contain `opt/mu300/vendor/u30pro/firmware/aic8800/*` (7 OEM Wi-Fi chipset firmware/config files) and `modem_*.xml` (3 ZTE modem descriptor XMLs) derived from reference `B28` `odm_a`/`vendor_a`, and **`f50pro-android-pkgs-pack.zip`** includes third-party binary `UFI-TOOLS.apk`. Disclosed cleanly in `THIRD_PARTY_NOTICES.md` & `README.md`.

### 9. Safety Assertion Automated Test Coverage (`VERIFIED` after expansion on `audit/release-quality-v1`)
All safety assertions now have automated unit/integration tests across `tests/test_plan_safety.py`, `tests/test_safety_coverage.py`, `tests/test_build_pure_python.py`, and `tests/test_sanitization.py`:
- `FORBIDDEN_PARTITIONS` rejection in `_op()` and `validate_plan_safety()`
- Profile 2 slot-`_a` write prohibition
- `flash_images.execute_flash` abort before write on live GPT mismatch, abort before `wof` on partition readback SHA-256 mismatch, and abort on `misc+2048` offset verify failure
- `host_network.audit_default_routes()` gateway hijack detection across both `RNDIS` and `UsbNcm`
- `fetch_assets` SHA-256 verification, nested APK digest enforcement, and zip-slip path traversal block
- `brom_backup.verify_backup_dir` `bare_metal_sprd3_ready=False` & `splloader_bak` warning
- `repack_vendor_boot_v4` DTB digest guard, `inspect_backup_dir` signature checks, and `apply_slot_a_from_openwrt` local digest pre-check
- Automated PII / private-key / clean OpenClash template scan across `git ls-files`

### 10. Status Classification Summary (`VERIFIED` / `PARTIAL` / `UNVERIFIED` / `BLOCKED`)
- **`VERIFIED`**: Clean Git source sanitization, `v1.0.0` HTTPS downloads + manifest SHA-256 integrity, fresh Windows `.venv` bootstrap + offline test suite, pure-Python `init_boot_a` / `trustos_noavb` / `boot_b` / `vendor_boot_b` builders (including bit-exact parity check against real `B15` stage3), upstream `B28` dual-boot (`5G NR SA` + Wi-Fi + Magisk + UFI + 5s switch).
- **`PARTIAL`**: Upstream `B15` dual-boot (installed, rooted, switched cleanly, but OpenWrt eSIM data `wan.up=0`/`net_red=1` at audit capture and used B28 ext4 base); Release `v1.0.0` asset cleanliness (`0` PII, yet includes `aic8800`/`modem_*.xml` OEM blobs & mis-targeted `.bat` in `qmk_driver_installer`).
- **`UNVERIFIED`**: First-ever live end-to-end execution of this refactored `kit.py` / `provision_openwrt.py` / `provision_android.py` CLI on `B28` or `B15`; standalone Profiles `1` & `2` via `kit.py`; `B15` live 5G eSIM WAN data under OpenWrt; Wi-Fi STA client.
- **`BLOCKED`**: Unassisted bare-metal `SPRD3` BootROM recovery when `SPL` or active `U-Boot` fails (requires external signed `UMS9632` `FDL1`/`FDL2`).

---

## Recommended Next Steps Before Tagging `v1.0.1` Production Release

1. Merge `audit/release-quality-v1` into `main` after review.
2. Execute controlled live end-to-end runs of `kit.py` on both `B28` and `B15` (including confirming `B15` OpenWrt eSIM WAN connectivity `wan.up=1` and exercising `device-usb set-net rndis permanent 1` reboot persistence).
3. For a clean `v1.0.1` Release asset refresh: strip `aic8800` / `modem_*.xml` OEM blobs from `openwrt-base` (extracting them on the fly from the user's own `super` dump) and fix `qmk_driver_installer\install_connected_drivers.bat` -> `unisoc_drivers.txt`.
