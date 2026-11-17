# P0 Safety Remediation Report & Release Candidate `v1.1.1-rc.1` Plan

- **Baseline Commit**: `cec1392` (`feat/multi-platform-host`, `tag: v1.1.0` — frozen; `main` @ `aa2deb6` untouched; `v1.1.0` tag and published assets untouched)
- **Remediation Branch**: `fix/p0-safety-remediation` (`4b6e2e8` -> `189123e` + doc/CI commit)
- **Scope**: All 6 P0 safety/reliability blockers (`P0-1` .. `P0-6`) + P1 multi-platform trust/privilege/documentation alignment + reproducible fault-injection test suite (`tests/test_p0_remediation.py`). Zero live device flashing, rebooting, slot switching, or host NIC changes performed.

---

## 1. P0 Remediation Matrix (`P0-1` through `P0-6`)

| ID | Commit | Baseline Defect (`cec1392`) | Remediation Implemented | Fault-Injection Verification (`pytest`) |
| :--- | :--- | :--- | :--- | :--- |
| **P0-1** | `4b6e2e8` | Flash errors still hit `finally: sess.close(reboot=True)` sending `reset` into a partially-flashed or wrong slot | `scripts/flash_images.py` separates success (`sess.close(reboot=True)`) from failure (`sess.close(reboot=False)` without `"reset"`), stops remaining ops & skips slot switch (`wof`), probes read-only diagnostics (`_probe_failure_diag`) when transport stays up without claiming infinite AutoD hold, and writes `flash_state.json` + `flash_failure_report.json` (`verified_partitions`, `pending_operations`, `failed_stage`, `reset_sent=false`, `slot_switched=false`) | `test_p0_1_flash_failure_never_reboots_or_switches_slot`: readback mismatch, live GPT mismatch, mid-stream USB disconnect, write timeout -> all verify zero `reset` / zero `wof` + persisted failure state |
| **P0-2** | `5f5c720` | Identical-model units (`MU3356` / `1782:4d00`) could mix backups/plans without unit-level cryptographic binding; `PROFILE_ALLOWED_*` bounds weren't embedded/enforced across paths | `scripts/common.py` (`compute_unit_identity_digest`, `PROFILE_ALLOWED_BROM_OPS`, `PROFILE_ALLOWED_OPENWRT_STAGE_OPS`), `inspect_backup.py`, `build_images.py` (`plan_version: 2`), `flash_images.py` (`validate_plan_safety`, `_verify_live_target_identity`), `provision_android.py`: binds plans to hashed non-zero read-only `prodnv`/`miscdata`/`persist` + GPT + build + optional `board_id` (zero raw PII/IMEI in logs), refuses weak/zero identity unless explicitly allowed, and rejects out-of-policy partitions/bounds | `test_p0_2_swapped_identical_model_device_rejected`: swapped Device B (same `MU3356`, different `prodnv`) aborts before any `write_part`/`wof`/`reset`; zero/weak identity rejected unless forced; forbidden/out-of-profile partitions blocked |
| **P0-3** | `0e73491` | Broad NIC name matching risked mutating phone USB tethering, USB-C docks, and falsely flagged normal `192.168.0.1` Wi-Fi routers as ZTE gateways | `scripts/host_network.py`: restricts selection (`select_target_usb_adapters`) to F50 Pro USB VID/PID (`1D6B:0104`, or `19D2` when opted in) using Windows PnP IDs, Linux sysfs `_walk_linux_sysfs_usb_ids`, and macOS `Hardware Port` / BSD `Device` / user-renamed `Network Service` correlation (`correlate_macos_net_candidates`); blocks ambiguous multi-target mutation; fixes `192.168.0.1` normal Wi-Fi false positive; adds `management` vs `internet-exit` modes & `restore_network_snapshot()` | `test_p0_3_targeted_nic_selection_ignores_phone_tether_usb_dock_and_wifi_192_168_0_1`: phone tether, Realtek USB-C dock, Wi-Fi `192.168.0.1`, ambiguous two-dongle setup, macOS renamed service, and snapshot restoration |
| **P0-4** | `8156ef1` | `provision_openwrt.py` unconditionally ran `device-usb set-net rndis permanent 1` + UCI mutation even when NCM/ECM already worked, breaking Linux/macOS host connectivity & masking USB re-enumeration | `scripts/provision_openwrt.py`: adds `resolve_host_usb_net_plan` (`usb_net_mode="auto"`, `usb_net_persist=False`) preserving working `ncm`/`ecm`/`rndis`, separates `install_usb_net_mode` vs `final_usb_net_mode`, wraps explicit mode switches in `_apply_usb_net_mode_transition` handling expected USB disconnect, re-verifies the same unit identity hash after re-enumeration, and raises `UsbNetModeSwitchTimeoutError` without misclassifying as flash failure | `test_p0_4_no_forced_permanent_rndis_and_safe_usb_mode_transition`: Linux/macOS NCM preserved (`0` `set-net rndis` calls); explicit NCM->RNDIS switch reconnects to same device cleanly; timeout raises `UsbNetModeSwitchTimeoutError`; device swap aborts |
| **P0-5** | `1adcc01` | Generated OpenWrt passwords didn't propagate cleanly; `verify_e2e.py` reported `wifi_device` (`phy0-ap0`) as slot & always returned exit `0`; `preflight` didn't gate missing tools before live actions | `scripts/common.py` (`AuthContext` with masked `__repr__`, `resolve_auth_context`), `provision_android.py`, `verify_e2e.py`, `kit.py`: threads `AuthContext` across provision->verify, parses real boot evidence (`/proc/cmdline`/`bootargs` -> `UNKNOWN` when absent), evaluates per-profile checks strictly (`PASS`/`FAIL`/`NOT_TESTED`/`NOT_APPLICABLE`), exits `1` on verification failure, adds `preflight --strict` & `assert_preflight_ready()` pre-live gates | `test_p0_5_auth_context_verify_verdicts_and_preflight_gate`: generated password via `openwrt-credentials.json` redacted in reports/errors; missing cmdline -> `UNKNOWN`; Profile 3 inactive Android -> `NOT_TESTED`; Profile 2 Android -> `NOT_APPLICABLE`; auth/`su`/`ports` failure -> `rc=1`; missing `spd_dump`/`paramiko` blocks preflight (`rc=1`) |
| **P0-6** | `189123e` | `kit.py auto` without `--execute` still ran HTTPS `fetch_and_extract()` and `run_brom_backup()` (`REBOOT_DEVICE` + `reset`) | `scripts/fetch_assets.py` (`offline_only=True`), `scripts/brom_backup.py` (`--authorize-device-reboot`), `scripts/kit.py`: adds pure offline `kit.py plan` & `kit.py auto` (without `--execute`) with zero HTTP/WebUI/BROM/SSH/ADB/NIC side effects, adds non-reboot read-only `kit.py probe`, and separates `network_downloads` / `device_read_ops` / `device_mutations` / `device_rebooted` | `test_p0_6_offline_plan_dry_run_and_probe_boundaries`: monkeypatches HTTP, `trigger_zte_webui_reboot`, `Popen`, `connect_ssh`, `_adb`, `isolate_usb_rndis_adapter` to `AssertionError`; verifies `plan` & dry-run `auto` trigger `0` calls and `probe` never reboots or mutates |

---

## 2. Four-Tier Verification Separation Matrix (Strict Non-Substitution)

> **Rule**: Compilation/packaging, Host unit/CI execution, USB transport handshakes, and real-device end-to-end verification are recorded independently below and never substituted for one another.

| Target / Environment | Tier 1: Compile / Package Integrity | Tier 2: Host Runtime / Automated Tests | Tier 3: Live USB Communication | Tier 4: Real-Device E2E Closed-Loop |
| :--- | :---: | :---: | :---: | :--- |
| **Repo Python Modules & Fault Suite (`fix/p0-safety-remediation`)** | `PASS` (pure Python 3.11 syntax/imports clean) | **`PASS` (`52 / 52` pytest cases on Windows `.venv` after `189123e`)**; CI on `ubuntu-latest`, `macos-latest`, `windows-latest` triggered via push | `N/A` (synthetic + monkeypatched mocks; no F50 Pro attached this turn) | `N/A` (explicitly prohibited by task scope: no flash, reboot, or slot switch) |
| **`B28` (`board_id=6`, Physical SIM)** | `PASS` (synthetic & image builder parity) | `PASS` (`build_profile` + P0 tests) | **`VERIFIED` *(upstream `codex-native-b28` 82-file `7,005,873,833` B dump)*** | **`VERIFIED` *(upstream hardware fact preserved: `_a` + `_b` + `5G NR SA` + Wi-Fi 6 + OpenClash + `5s` switch)*** / `UNVERIFIED` *(via refactored `kit.py` CLI)* |
| **`B15` (`board_id=1`, Built-in Dual eSIM)** | `PASS` (`v1.0.0` audit confirmed bit-exact stage3 parity) | `PASS` (DTB & offset `0x981ec` fixtures) | **`VERIFIED` *(upstream `b15-...` `SPRD4:AutoD` dump & flash)*** | **`PARTIAL` *(upstream hardware dual-boot + `5s` roundtrip verified)***; **paid eSIM cellular WAN intentionally NOT tested per user decision (non-blocker)** |
| **Linux `x86_64` Host** | `PASS` (`host_tools_linux_x64`, `musl` v251) | `PASS` (GitHub Actions `ubuntu-latest`: `pytest` + `bootstrap.sh` + `preflight --strict` + `plan` + `spd_dump -h` + `adb version`) | `UNVERIFIED` (no physical F50 Pro plugged into Linux x64 host) | `UNVERIFIED` |
| **macOS Universal (`arm64` + `x86_64`) Host** | `PASS` (`Mach-O` universal `spd_dump` + `platform-tools 37.0.1`) | `PASS` (GitHub Actions `macos-latest` + unit `networksetup` / `SPUSBDataType` parser tests) | `UNVERIFIED` (no physical F50 Pro plugged into macOS host) | `UNVERIFIED` |
| **Linux `arm64` (`aarch64`) Host** | `PASS` (`musl` static binary packaged) | **`NOT CI-TESTED`** (GitHub-hosted runners lack native ARM64 Ubuntu in matrix; parser/dispatch unit-tested only) | `UNVERIFIED` | `UNVERIFIED` |
| **Android Termux OTG (`arm64`) Host** | `PASS` (`spd_dump-su` & NDK `spd_dump-termux-usb`) | `PARTIAL` (CLI/argv construction tests only; not run inside Termux runtime) | `UNVERIFIED` | `UNVERIFIED` *(Non-root `--usb-fd` is single-grant and does not survive reset/re-enumeration -> **EXPERIMENTAL / non-turnkey**)* |

---

## 3. P1 Multi-Platform Trust & Documentation Alignment Applied

1. **Pinned References vs Mutable `main`**: `README.md`, `AGENT-FLASH.md`, and `docs/multi-platform-host.md` now instruct cloning/fetching by explicit Release tag (`--branch v1.1.0 --depth 1` / future immutable `v1.1.1-rc.1` tag) rather than unpinned `main`.
2. **Integrity vs Signature Boundary**: Explicitly documented that `assets/release-manifest.json` enforces **SHA-256 checksum integrity**, **not** cryptographic publisher signatures (GPG/Cosign/GitHub Attestation).
3. **Least-Privilege Guidance**: Clarified preferring Linux `assets/udev/99-unisoc-f50pro.rules` + non-root `preflight`/`plan` execution and scoping `sudo` via `--spd-mode sudo` rather than running the full Python workflow as `root`.
4. **Non-Root Android OTG Boundary**: Explicitly clarified why `spd_dump-termux-usb --usb-fd` is not a turnkey one-click loop (`LIBUSB_OPTION_NO_DEVICE_DISCOVERY` disables `--kickto 2` auto-reconnect across reboots).
5. **CI Workflow Coverage**: Updated `.github/workflows/ci-host-tests.yml` to run full `pytest`, `bootstrap.sh`, `kit.py preflight --strict --operation backup`, and `kit.py plan` on pushes to `fix/p0-safety-remediation` across `ubuntu-latest`, `macos-latest`, and `windows-latest`.

---

## 4. Immutable `v1.1.1-rc.1` Release Candidate Publishing Plan (Do NOT Publish Without Approval)

- **Freeze Guarantee**: `v1.1.0` tag, release commit `cec1392`, and all `v1.1.0` downloadable release archives remain completely untouched.
- **Draft-First Immutable Release Flow** (once live pilot sign-off & merge/tag authorization is granted):
  1. Verify all GitHub Actions jobs (`ubuntu-latest`, `macos-latest`, `windows-latest`) on `fix/p0-safety-remediation` report green with zero failures or skipped assertions.
  2. Create a **Draft Release** tagged `v1.1.1-rc.1` targeting the reviewed commit SHA (`fix/p0-safety-remediation` merge commit or RC tag — not moving `v1.1.0`).
  3. Upload release archive set & generate SHA-256 manifest matching exact uploaded artifact sizes/digests (`test_sanitization.py::test_release_manifest_matches_local_dist_when_present`), plus archive full build/test provenance.
  4. Download every uploaded RC archive in a clean directory, verify SHA-256s match byte-for-byte, and run `.venv\Scripts\python.exe scripts\kit.py preflight --strict` + `plan`.
  5. Only after verification passes, publish `v1.1.1-rc.1` as a prerelease (immutable tag; never overwrite existing release assets).

---

## 5. Minimal Live-Device Pilot Proposal (Awaiting Explicit User Authorization)

Recommended ordered, lowest-risk physical verification steps once you authorize connecting a test F50 Pro (`B28` or `B15`):

1. **Step 1 (Zero Reboot / Read-Only Probe)**: Run `kit.py probe --profile 3-dual-full --out build/pilot/probe.json` while F50 Pro is already booted to confirm targeted USB NIC detection (`1D6B:0104`), zero `192.168.0.1` false positives, USB mode detection (`ncm`/`rndis`), and non-zero exit behavior.
2. **Step 2 (Explicitly Authorized Read-Only BROM Dump)**: Run `kit.py backup --output-dir build/pilot/backup --authorize-device-reboot --webui-password "<PW>"` and verify `device_identity` SHA-256 metadata (`prodnv`/`miscdata`).
3. **Step 3 (100% Offline Plan Review)**: Run `kit.py plan --profile 3-dual-full --work-dir build/pilot --openclash` to generate `flash_plan.json` bound to that exact device's cryptographic identity.
4. **Step 4 (Authorized Live Write Pilot — Only After Plan Approval)**: Execute `kit.py auto --profile 3-dual-full --work-dir build/pilot --reuse-backup --generate-password --usb-net-mode auto --execute` on one designated pilot unit (retaining preserved `B28` upstream facts; keeping `B15` paid eSIM WAN excluded per user decision).
