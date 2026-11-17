# Third-Party Components & Licenses

This repository provides original orchestration scripts, offline patch builders, device hardware profiles, tests, and documentation under the MIT License. Pre-built third-party open-source/upstream tools referenced in `assets/release-manifest.json` and the `v1.0.0` Release bundle retain their respective licenses:

1. **OpenWrt (`25.12.5` aarch64_generic) & packages (`dnsmasq-full`, `ruby`, `luci-compat`, `unzip`, etc.)** — GPL-2.0 / Apache-2.0 / respective package licenses (`https://openwrt.org/`).
2. **`u30pro_openwrt` (`devices/f50pro` kernel/initramfs/userspace framework)** — `https://github.com/kanoqwq/u30pro_openwrt`.
3. **Magisk (`1e3edb88` canary `28103`)** — GPL-3.0 (`https://github.com/topjohnwu/Magisk`).
4. **UFI-TOOLS (`4.0.0` `com.minikano.f50_sms`)** — bundled binary APK from upstream `zte-f50pro-macos-toolkit`.
5. **`luci-app-openclash` (`0.48.002`)** — GPL-3.0 (`https://github.com/vernesong/OpenClash`).
6. **Mihomo Core (`v1.19.34` linux-arm64)** — GPL-3.0 (`https://github.com/MetaCubeX/mihomo`).
7. **`spd_dump` (`spd_dump_251` / `spreadtrum_flash`)** — GPL-2.0 (`https://github.com/ilyakurdyukov/spreadtrum_flash`; open-source `TomKing062/spreadtrum_flash` commit `607f701` compiled from source via CI for macOS 11.0+ Universal `arm64+x86_64` and Android NDK `--usb-fd`, plus `TomKing062/action_spd_dump_it` Linux musl `e49d4de` & Win64 builds).
8. **Android SDK Platform Tools (`adb`, `fastboot`, `sqlite3`, `mke2fs`)** — Google official `37.0.1` (`win32`, `linux`, `darwin` Universal) under Apache-2.0 / Android SDK License (`https://developer.android.com/tools/releases/platform-tools`).
9. **GeoSite / Country MMDB** — upstream GeoIP/GeoSite data bundles (clean database files only, zero proxy nodes or subscriptions).

## Release v1.0.0 Binary Bundle Disclosure & Sanitization Notes

- **Git source tree (`54` tracked files on `main`)**: Contains only pure-Python orchestration scripts, OpenWrt `ucode`/JS/shell patches, clean OpenClash `proxies: []` templates, documentation, and tests. Contains zero OEM partition dumps, zero IMEIs/SNs/ICCIDs, zero NV calibration files, zero personal passwords/keys, and zero device backups.
- **GitHub Release `v1.0.0` binary bundles (external assets referenced by SHA-256)**:
  - `f50pro-base-openwrt-25.12.5-pack.tar.xz` (`openwrt-f50pro-25.12.5-base-rootfs.ext4`) includes `opt/mu300/vendor/u30pro/firmware/aic8800/*` Wi-Fi chipset firmware blobs and `modem_*.xml` hardware descriptors derived from reference `B28` `odm_a`/`vendor_a` images (no NV calibration, IMEIs, host SSH keys, or personal accounts).
  - `f50pro-android-pkgs-pack.zip` includes prebuilt `UFI-TOOLS.apk` from upstream `zte-f50pro-macos-toolkit` alongside official `Magisk-canary-28103.apk`.
  - A future `v1.0.1` clean-room enhancement can extract `aic8800`/modem blobs locally at runtime from each user's own BROM `super` backup if redistributable base rootfs builds must strip all OEM firmware binaries.
