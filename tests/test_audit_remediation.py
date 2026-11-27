"""Regression tests covering all three-way audit remediation items and post-review hardening."""
from __future__ import annotations

import errno
import gzip
import hashlib
import io
import json
import re
import shutil
import struct
import subprocess
import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from brom_backup import (
    _parse_sha256sums,
    parse_partition_xml,
    run_brom_backup,
    verify_backup_dir,
)
from build_images import build_profile
from common import (
    ASSETS_DIR,
    REPO_ROOT,
    decompress_lz4_legacy,
    parse_newc_cpio,
    repack_vendor_boot_v4,
    sha256_bytes,
)
from fetch_assets import _safe_extract_tar, fetch_and_extract
from flash_images import execute_flash, validate_plan_safety
from host_network import (
    _ps_quote,
    _save_initial_snapshot,
    restore_network_snapshot,
    select_target_usb_adapters,
)
from kit import build_parser, main as kit_main, run_preflight
from provision_android import apply_slot_a_from_openwrt, provision_android
from provision_openwrt import (
    _apply_usb_net_mode_transition,
    _build_builtin_kmods_apk_v2,
    _ensure_5s_buttons,
    _install_openclash_offline,
    _merge_rc_local_hook,
    _set_root_password_ssh,
    provision_openwrt,
    resolve_host_usb_net_plan,
    wait_for_openwrt_ssh,
)
from verify_e2e import evaluate_e2e_checks


def test_backup_integrity_rejects_tamper_duplicates_traversal_and_missing_manifest(
    synthetic_env: dict[str, Path], tmp_path: Path
) -> None:
    """SHA256SUMS.txt is verified without overwriting, rejects traversal/duplicates, and fresh dumps refuse non-empty dirs."""
    bdir = tmp_path / "bak"
    shutil.copytree(synthetic_env["backup_dir"], bdir)
    (bdir / "SHA256SUMS.txt").unlink(missing_ok=True)
    rep1 = verify_backup_dir(bdir)
    assert rep1["checks_passed"] is True
    assert rep1["sha256sums_mode"] == "generated_fresh"
    orig_sums = (bdir / "SHA256SUMS.txt").read_text(encoding="utf-8")
    assert "partition_list.xml" in orig_sums

    # Equal-length tamper of trustos_a must FAIL verification, preserve SHA256SUMS.txt, and update verification_report.json
    tos_p = bdir / "trustos_a"
    raw = bytearray(tos_p.read_bytes())
    raw[-1] ^= 0xFF
    tos_p.write_bytes(bytes(raw))
    with pytest.raises(ValueError, match="Backup integrity mismatch on trustos_a"):
        verify_backup_dir(bdir)
    assert (bdir / "SHA256SUMS.txt").read_text(encoding="utf-8") == orig_sums
    fail_rep = json.loads((bdir / "verification_report.json").read_text(encoding="utf-8"))
    assert fail_rep["checks_passed"] is False

    # Manifest parser rejects duplicate filenames and path traversal entries
    bad_dup = tmp_path / "dup.txt"
    bad_dup.write_text(f"{'a'*64}  misc\n{'a'*64}  misc\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate filename"):
        _parse_sha256sums(bad_dup)
    bad_trav = tmp_path / "trav.txt"
    bad_trav.write_text(f"{'a'*64}  ../outside\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Unsafe filename"):
        _parse_sha256sums(bad_trav)

    # require_existing_manifest refuses directory with verification_report.json but deleted SHA256SUMS.txt
    bdir2 = tmp_path / "bak_no_manifest"
    shutil.copytree(synthetic_env["backup_dir"], bdir2)
    (bdir2 / "SHA256SUMS.txt").unlink(missing_ok=True)
    (bdir2 / "verification_report.json").write_text('{"checks_passed": true}', encoding="utf-8")
    with pytest.raises(ValueError, match="Missing required backup integrity manifest"):
        verify_backup_dir(bdir2, require_existing_manifest=True)

    # Early XML / misc BCAB corruption MUST overwrite any stale verification_report.json with checks_passed=False
    bdir_bad_xml = tmp_path / "bak_bad_xml"
    shutil.copytree(synthetic_env["backup_dir"], bdir_bad_xml)
    (bdir_bad_xml / "partition_list.xml").write_text("<not valid xml", encoding="utf-8")
    with pytest.raises(ValueError, match="Failed to parse partition_list.xml"):
        verify_backup_dir(bdir_bad_xml)
    assert json.loads((bdir_bad_xml / "verification_report.json").read_text(encoding="utf-8"))["checks_passed"] is False

    bdir_no_xml = tmp_path / "bak_no_xml"
    shutil.copytree(synthetic_env["backup_dir"], bdir_no_xml)
    (bdir_no_xml / "partition_list.xml").unlink()
    with pytest.raises(FileNotFoundError):
        verify_backup_dir(bdir_no_xml)
    assert json.loads((bdir_no_xml / "verification_report.json").read_text(encoding="utf-8"))["checks_passed"] is False

    bdir_bad_misc = tmp_path / "bak_bad_misc"
    shutil.copytree(synthetic_env["backup_dir"], bdir_bad_misc)
    (bdir_bad_misc / "misc").write_bytes(b"\x00" * (1 << 20))
    with pytest.raises(ValueError, match="Invalid misc bootloader_control"):
        verify_backup_dir(bdir_bad_misc)
    assert json.loads((bdir_bad_misc / "verification_report.json").read_text(encoding="utf-8"))["checks_passed"] is False

    # Fresh live backup refuses non-empty directory even with non-CORE files like ztecfg/persist
    stale_dir = tmp_path / "stale_non_core"
    stale_dir.mkdir()
    (stale_dir / "ztecfg").write_bytes(b"OLD")
    with pytest.raises(FileExistsError, match="already contains backup artifacts"):
        run_brom_backup(stale_dir, tools_dir=synthetic_env["tools_dir"], authorize_device_reboot=True)


def test_apply_slot_a_verifies_identity_stock_sha_capacity_and_two_stage_upload(
    synthetic_env: dict[str, Path], tmp_path: Path
) -> None:
    """Profile 3 OpenWrt -> Android _a staging checks unit identity, stock SHA, capacity, and stages BOTH uploads before any dd."""
    out = synthetic_env["out_dir"] / "p3_stage"
    plan = build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="3-dual-full",
        out_dir=out,
        tools_dir=synthetic_env["tools_dir"],
        adb_pubkey_path=synthetic_env["adb_pubkey"],
    )
    bdir = synthetic_env["backup_dir"]

    # 1. Swapped unit identity (ztecfg mismatch) -> abort with zero dd calls
    ssh_swap = MagicMock()
    cmds_swap: list[str] = []

    def _run_swap(client, cmd, *, check=True, timeout=60.0):
        cmds_swap.append(cmd)
        if "/dev/block/by-name/ztecfg" in cmd:
            return 0, "0" * 64 + "\n", ""
        return 0, "", ""

    with (
        patch("provision_android.wait_for_openwrt_ssh", return_value=ssh_swap),
        patch("provision_android.ssh_run", side_effect=_run_swap),
    ):
        with pytest.raises(RuntimeError, match="Target device identity mismatch"):
            apply_slot_a_from_openwrt(plan, isolate_host=False)
    assert not any("dd if=" in c for c in cmds_swap)

    # 2. Second image (init_boot_a) corrupted locally -> abort BEFORE connecting SSH
    bad_plan = json.loads(json.dumps(plan))
    bad_plan["android_a_stage"]["init_boot_a"]["sha256"] = "f" * 64
    with patch("provision_android.wait_for_openwrt_ssh", side_effect=AssertionError("Must fail before SSH")):
        with pytest.raises(ValueError, match="Digest mismatch on local init_boot_a"):
            apply_slot_a_from_openwrt(bad_plan, isolate_host=False)

    # 3. Stock SHA mismatch on init_boot_a -> abort BEFORE dd writes trustos_a
    cmds_stock: list[str] = []

    def _run_stock(client, cmd, *, check=True, timeout=60.0):
        cmds_stock.append(cmd)
        if "blockdev --getsize64" in cmd:
            return 0, str(16 * 1024 * 1024) + "\n", ""
        for pname in ("ztecfg", "persist", "vendor_boot_a", "trustos_a"):
            if f"/dev/block/by-name/{pname}" in cmd:
                return 0, sha256_bytes((bdir / pname).read_bytes()) + "\n", ""
        if "/dev/block/by-name/init_boot_a" in cmd:
            return 0, "a" * 64 + "\n", ""
        return 0, "", ""

    with (
        patch("provision_android.wait_for_openwrt_ssh", return_value=MagicMock()),
        patch("provision_android.ssh_run", side_effect=_run_stock),
    ):
        with pytest.raises(RuntimeError, match="stock SHA-256 mismatch"):
            apply_slot_a_from_openwrt(plan, isolate_host=False)
    assert not any("dd if=" in c for c in cmds_stock)

    # 4. Second SFTP upload fails -> abort with ZERO dd writes to trustos_a!
    cmds_up: list[str] = []
    put_calls = {"n": 0}

    def _run_up(client, cmd, *, check=True, timeout=60.0):
        cmds_up.append(cmd)
        if "blockdev --getsize64" in cmd:
            return 0, str(16 * 1024 * 1024) + "\n", ""
        for pname in ("ztecfg", "persist", "vendor_boot_a", "trustos_a", "init_boot_a"):
            if f"/dev/block/by-name/{pname}" in cmd:
                return 0, sha256_bytes((bdir / pname).read_bytes()) + "\n", ""
        if "sha256sum /tmp/trustos_a.new.img" in cmd:
            return 0, plan["android_a_stage"]["trustos_a"]["sha256"] + "\n", ""
        return 0, "", ""

    def _fail_second_put(_sftp, _data, remote_path, mode=0o644):
        put_calls["n"] += 1
        if put_calls["n"] == 2:
            raise OSError("Simulated SFTP drop on second upload")

    with (
        patch("provision_android.wait_for_openwrt_ssh", return_value=MagicMock()),
        patch("provision_android.ssh_run", side_effect=_run_up),
        patch("provision_android.open_remote_fs", return_value=MagicMock()),
        patch("provision_android.sftp_put_bytes", side_effect=_fail_second_put),
    ):
        with pytest.raises(OSError, match="Simulated SFTP drop"):
            apply_slot_a_from_openwrt(plan, isolate_host=False)
    assert not any("dd if=" in c for c in cmds_up)

    # 5. Capacity too small -> abort before any write
    def _run_small_cap(client, cmd, *, check=True, timeout=60.0):
        if "blockdev --getsize64" in cmd:
            return 0, "1024\n", ""
        for pname in ("ztecfg", "persist", "vendor_boot_a"):
            if f"/dev/block/by-name/{pname}" in cmd:
                return 0, sha256_bytes((bdir / pname).read_bytes()) + "\n", ""
        return 0, "", ""

    with (
        patch("provision_android.wait_for_openwrt_ssh", return_value=MagicMock()),
        patch("provision_android.ssh_run", side_effect=_run_small_cap),
    ):
        with pytest.raises(ValueError, match="exceeds live block device capacity"):
            apply_slot_a_from_openwrt(plan, isolate_host=False)


def test_ufi_ttyd_hardening_and_profile3_rollback_token_cold_reboot(
    synthetic_env: dict[str, Path], tmp_path: Path
) -> None:
    """Hardened ttyd has zero hardcoded passwords/unbound fallback; Profile 3 embeds per-build rollback token & verifies boot_id."""
    login_sh = (ASSETS_DIR / "android-scripts" / "ufi-ttyd-login.sh").read_text(encoding="utf-8")
    daemon_tpl = (ASSETS_DIR / "android-scripts" / "ufi-tools-daemon.sh.tpl").read_text(encoding="utf-8")
    assert "BACKUP_PASS" not in login_sh
    assert not re.search(r"[0-9a-fA-F]{64}", login_sh)
    assert "/data/adb/ufi-ttyd.sha256" in login_sh
    assert "mode=0600" in daemon_tpl
    assert "mode=0666" not in daemon_tpl
    assert "FW_OK=0" in daemon_tpl
    assert "/proc/net/if_inet6" in daemon_tpl
    assert "EXPECTED_TTYD_ARGS=" in daemon_tpl
    # Must NEVER launch ttyd without --interface
    ttyd_launches = [ln for ln in daemon_tpl.splitlines() if "setsid" in ln and "/ttyd" in ln]
    assert ttyd_launches and all("--interface" in ln and '"$LOGIN_SCRIPT"' in ln for ln in ttyd_launches)

    # Profile 3 embeds unique rollback_token into overlay-return-b.sh so stale DONE files from prior installs do NOT disarm it
    out3 = synthetic_env["out_dir"] / "p3_rollback"
    plan3 = build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="3-dual-full",
        out_dir=out3,
        tools_dir=synthetic_env["tools_dir"],
        adb_pubkey_path=synthetic_env["adb_pubkey"],
    )
    token = plan3["android_a_stage"]["rollback_token"]
    assert re.fullmatch(r"[0-9a-f]{32}", token)
    # Rebuilding into the same out_dir with the same backup manifest preserves rollback_token for idempotent resume!
    plan3_retry = build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="3-dual-full",
        out_dir=out3,
        tools_dir=synthetic_env["tools_dir"],
        adb_pubkey_path=synthetic_env["adb_pubkey"],
    )
    assert plan3_retry["android_a_stage"]["rollback_token"] == token
    assert plan3_retry["android_a_stage"]["init_boot_a"]["sha256"] == plan3["android_a_stage"]["init_boot_a"]["sha256"]

    ib_raw = Path(plan3["android_a_stage"]["init_boot_a"]["file"]).read_bytes()
    k_sz, r_sz = struct.unpack_from("<II", ib_raw, 8)
    r_off = 4096 + ((k_sz + 4095) // 4096) * 4096
    entries = {e["name"]: e["data"] for e in parse_newc_cpio(decompress_lz4_legacy(ib_raw[r_off : r_off + r_sz]))}
    ret_sh = entries["overlay.d/sbin/f50pro-test-return-b.sh"].decode("utf-8")
    assert f'TOKEN="{token}"' in ret_sh
    assert "is_disarmed" in ret_sh

    # Verify provision_android writes rollback token strictly AFTER verified UUID boot_id change & hardened ttyd check
    (synthetic_env["tools_dir"] / "openwrt-base" / "mu300-keys").write_bytes(b"KEYS")
    events: list[str] = []
    boot_ids = iter(["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"])

    def _fake_adb(adb_exe, args, *, serial=None, check=True, timeout=60.0):
        joined = " ".join(args)
        events.append(f"adb:{joined}")
        if "boot_id" in joined:
            return next(boot_ids)
        if "pm list packages" in joined:
            return "package:com.minikano.f50_sms.extra uid:10999\npackage:com.minikano.f50_sms uid:10234\n"
        if "persist.sys.usb.config" in joined:
            return "charging,adb"
        return ""

    def _id_su_reply(plan_d: dict, script: str) -> str | None:
        ident = plan_d["device_identity"]
        if "board_id" in script:
            return f"{ident.get('board_id', '6')}\n"
        for pname, pspec in (ident.get("unit_identity_partitions") or {}).items():
            if f"/dev/block/by-name/{pname}" in script:
                return f"{pspec['sha256']}\n"
        if "/dev/block/by-name/vendor_boot_a" in script:
            return f"{ident['firmware_build']['vendor_boot_a_sha256']}\n"
        return None

    def _fake_su(adb_exe, script, *, serial=None, check=True, timeout=60.0):
        events.append(f"su:{script}")
        id_out = _id_su_reply(plan3, script)
        if id_out is not None:
            return id_out
        if "ss -tln" in script:
            return 'LISTEN 0 128 0.0.0.0:2333 0.0.0.0:*\nLISTEN 0 128 192.168.0.1:1146 0.0.0.0:* users:(("ttyd",pid=999,fd=5))\n'
        if "grep '[t]tyd'" in script:
            return "root 999 1 0 ttyd --writable --port 1146 --interface br0 /data/adb/ufi-ttyd-login.sh\n"
        return ""

    with (
        patch("provision_android.resolve_tool", return_value=tmp_path / "adb"),
        patch("provision_android.apply_slot_a_from_openwrt", return_value={"trustos_a": {"status": "written_verified"}}),
        patch("provision_android.wait_for_adb_slot_a", return_value="_a"),
        patch("provision_android._adb", side_effect=_fake_adb),
        patch("provision_android._su", side_effect=_fake_su),
        patch("provision_android.time.sleep"),
    ):
        res = provision_android(
            plan_path=out3 / "flash_plan.json",
            tools_dir=synthetic_env["tools_dir"],
            return_to_openwrt=False,
        )

    assert res["ufi_uid"] == 10234
    assert res["hardened_ttyd_verified"] is True
    assert Path(res["ttyd_credentials_file"]).is_file()
    idx_clear = next(i for i, e in enumerate(events) if "rm -f /data/adb/f50pro-android-test-complete" in e)
    idx_reboot = next(i for i, e in enumerate(events) if e == "adb:reboot")
    idx_ports = next(i for i, e in enumerate(events) if "ss -tln" in e)
    idx_done = next(i for i, e in enumerate(events) if "f50pro-android-test-complete" in e and token in e)
    assert idx_clear < idx_reboot < idx_ports < idx_done

    # Unchanged UUID boot_id after adb reboot must FAIL instead of disarming rollback
    with (
        patch("provision_android.resolve_tool", return_value=tmp_path / "adb"),
        patch("provision_android.apply_slot_a_from_openwrt", return_value={}),
        patch("provision_android.wait_for_adb_slot_a", return_value="_a"),
        patch(
            "provision_android._adb",
            side_effect=lambda _e, a, **k: "11111111-1111-4111-8111-111111111111"
            if "boot_id" in " ".join(a)
            else ("package:com.minikano.f50_sms uid:10234\n" if "pm list" in " ".join(a) else ""),
        ),
        patch("provision_android._su", side_effect=lambda _e, s, **k: _id_su_reply(plan3, s) or ""),
        patch("provision_android.time.sleep"),
        pytest.raises(RuntimeError, match="invalid or unchanged /proc/sys/kernel/random/boot_id"),
    ):
        provision_android(plan_path=out3 / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], return_to_openwrt=False)


def test_openclash_builtin_kmods_apk_v2_and_subscription_preservation(tmp_path: Path) -> None:
    """OpenClash offline strips kernel localversion for valid APK v2 version, swaps dnsmasq cleanly, and preserves subscriptions."""
    # 1. Realistic F50 Pro kernel string '6.12.94-u30pro-p1' -> valid Alpine APK version '6.12.94-r1'
    apk_bytes = _build_builtin_kmods_apk_v2("6.12.94-u30pro-p1", ["kmod-tun", "kmod-nf-conntrack-netlink"])
    first_gz = gzip.GzipFile(fileobj=io.BytesIO(apk_bytes), mode="rb")
    ctrl_tar = first_gz.read()
    with tarfile.open(fileobj=io.BytesIO(ctrl_tar), mode="r:") as tf:
        pkginfo = tf.extractfile(".PKGINFO").read().decode("utf-8")
    assert "pkgname = f50pro-builtin-kmods" in pkginfo
    assert "pkgver = 6.12.94-r1" in pkginfo
    assert "u30pro" not in pkginfo
    assert "provides = kmod-tun=6.12.94-r1" in pkginfo
    assert "provides = kmod-nf-conntrack-netlink=6.12.94-r1" in pkginfo
    second_off = apk_bytes.find(b"\x1f\x8b", 2)
    assert second_off > 0
    expected_datahash = hashlib.sha256(apk_bytes[second_off:]).hexdigest()
    assert f"datahash = {expected_datahash}" in pkginfo

    # 2. _install_openclash_offline uses `apk del --no-network dnsmasq && apk add` (NOT bare '!dnsmasq' which excludes dnsmasq-full)
    tools = tmp_path / "tools"
    oc = tools / "openclash-offline" / "packages"
    oc.mkdir(parents=True)
    (oc / "dnsmasq-full-2.93-r2.apk").write_bytes(b"FAKE_DNS")
    (oc / "luci-app-openclash-0.48.002.apk").write_bytes(b"FAKE_OC")
    (tools / "openclash-offline" / "mihomo-linux-arm64.gz").write_bytes(gzip.compress(b"ELF_MIHOMO"))
    (tools / "openclash-offline" / "GeoSite.dat").write_bytes(b"GEO")
    (tools / "openclash-offline" / "Country.mmdb").write_bytes(b"MMDB")

    ssh = MagicMock()
    sftp = MagicMock()
    ran_cmds: list[str] = []
    uploaded: list[str] = []

    def _fake_ssh(client, cmd, *, check=True, timeout=60.0):
        ran_cmds.append(cmd)
        if "has_apk=" in cmd:
            return (
                0,
                "has_apk=1\nkver=6.12.94-u30pro-p1\nhas_dnsmasq=1\nhas_dnsmasq_full=0\nhas_kmod_tun=0\nhas_kmod_ct=0\nbuiltin_tun=1\nbuiltin_ct=1\n",
                "",
            )
        return 0, "", ""

    with (
        patch("provision_openwrt.ssh_run", side_effect=_fake_ssh),
        patch("provision_openwrt.sftp_put_bytes", side_effect=lambda _s, _d, p, mode=0o644: uploaded.append(p)),
    ):
        res = _install_openclash_offline(ssh, sftp, tools_dir=tools)

    assert res["builtin_kmod_provides"] == ["kmod-tun", "kmod-nf-conntrack-netlink"]
    assert any("f50pro-builtin-kmods-6.12.94-r1.apk" in p for p in uploaded)
    assert any("--simulate add" in c and "/tmp/oc-sim" in c and "--force-non-repository" in c and "--repositories-file /dev/null" in c for c in ran_cmds)
    apk_cmd = next(c for c in ran_cmds if "apk del --no-network" in c and "dnsmasq && apk add" in c)
    assert "oc-dnsmasq-bak.tar" in apk_cmd
    assert "--force-non-repository" in apk_cmd
    assert "!dnsmasq" not in apk_cmd
    assert "f50pro-builtin-kmods-6.12.94-r1.apk" in apk_cmd

    # Re-run when dnsmasq-full is already installed must NOT run `apk del dnsmasq`
    rerun_cmds: list[str] = []
    with (
        patch(
            "provision_openwrt.ssh_run",
            side_effect=lambda _c, cmd, **k: (
                rerun_cmds.append(cmd)
                or (
                    0,
                    "has_apk=1\nkver=6.12.94-u30pro-p1\nhas_dnsmasq=0\nhas_dnsmasq_full=1\nhas_kmod_tun=1\nhas_kmod_ct=1\nbuiltin_tun=1\nbuiltin_ct=1\n"
                    if "has_apk=" in cmd
                    else "",
                    "",
                )
            ),
        ),
        patch("provision_openwrt.sftp_put_bytes"),
    ):
        res_rerun = _install_openclash_offline(ssh, sftp, tools_dir=tools)
    assert res_rerun["builtin_kmod_provides"] == []
    assert not any("apk del" in c for c in rerun_cmds)
    assert any("apk add" in c and "--force-non-repository" in c for c in rerun_cmds)

    # 3. Missing built-in module in kernel modules.builtin must FAIL instead of faking provides
    def _fake_ssh_no_tun(client, cmd, *, check=True, timeout=60.0):
        if "has_apk=" in cmd:
            return (
                0,
                "has_apk=1\nkver=6.12.94-u30pro-p1\nhas_dnsmasq=1\nhas_kmod_tun=0\nhas_kmod_ct=0\nbuiltin_tun=0\nbuiltin_ct=1\n",
                "",
            )
        return 0, "", ""

    with (
        patch("provision_openwrt.ssh_run", side_effect=_fake_ssh_no_tun),
        patch("provision_openwrt.sftp_put_bytes"),
        pytest.raises(RuntimeError, match="kmod-tun"),
    ):
        _install_openclash_offline(ssh, sftp, tools_dir=tools)

    # 4. openclash-uci-apply.sh preserves existing template.yaml and ANY non-empty user config_path
    apply_sh = (ASSETS_DIR / "openwrt-patch" / "openclash-clean" / "openclash-uci-apply.sh").read_text(encoding="utf-8")
    assert "if [ ! -f /etc/openclash/config/template.yaml ]" in apply_sh
    assert 'if [ -z "$CUR_CFG" ]' in apply_sh


def test_openwrt_provisioning_hardening_guards(synthetic_env: dict[str, Path], tmp_path: Path) -> None:
    """Cover --generate-password guard, USB post-mode & rc=-1 drop, rc.local merge/read-error, apostrophe redaction, SSH close."""
    # 1. --generate-password without --out-dir must refuse before SSH
    with pytest.raises(ValueError, match="--generate-password requires --out-dir"):
        provision_openwrt(
            profile_id="2-dual-stock-openwrt",
            generate_password=True,
            out_dir=None,
            tools_dir=synthetic_env["tools_dir"],
        )

    # 2. _apply_usb_net_mode_transition handles rc=-1 transport drop AND fails when post-reconnect mode stayed 'ncm'
    ssh_pre, ssh_post = MagicMock(), MagicMock()
    plan_sw = resolve_host_usb_net_plan(
        host_platform="win64", current_mode="ncm", requested_mode="rndis", persist_mode=True
    )

    def _still_ncm(client, cmd, *, check=True, timeout=60.0):
        if "device-usb set-net" in cmd:
            return -1, "", ""  # simulated abrupt channel drop on live re-enumeration
        if "board_id=" in cmd:
            return 0, "board_id=6\nusb_mode=ncm\nhost_hash=h1\n", ""
        return 0, "", ""

    with (
        patch("provision_openwrt.ssh_run", side_effect=_still_ncm),
        patch("provision_openwrt.wait_for_openwrt_ssh", return_value=ssh_post),
        patch("provision_openwrt.time.sleep"),
        pytest.raises(RuntimeError, match="did not take effect"),
    ):
        _apply_usb_net_mode_transition(
            ssh_pre,
            plan=plan_sw,
            pre_identity={"board_id": "6", "usb_mode": "ncm", "host_hash": "h1"},
            openwrt_host="192.168.77.1",
            pw_candidates=("",),
            isolate_host=False,
            target_iface=None,
            usb_topology=None,
            out_dir=tmp_path,
        )
    ssh_post.close.assert_called_once()

    # 3. _merge_rc_local_hook preserves user commands, ignores commented marker, handles `exit 0 # comment`, and is idempotent
    hook_txt = (ASSETS_DIR / "openwrt-patch" / "buttons" / "rc.local").read_text(encoding="utf-8")
    existing = "#!/bin/sh\n# note mentioning .f50pro-switch-linux\n/usr/bin/my-custom-cmd &\nexit 0 # done\n"
    merged1 = _merge_rc_local_hook(existing, hook_txt).decode("utf-8")
    assert "/usr/bin/my-custom-cmd &" in merged1
    assert "# BEGIN f50pro-switch-linux" in merged1
    assert merged1.index("# BEGIN f50pro-switch-linux") < merged1.index("exit 0 # done")
    assert _merge_rc_local_hook(merged1, hook_txt).decode("utf-8") == merged1

    # 4. _ensure_5s_buttons rejects mismatched mu300-sysd BEFORE writing anything AND re-raises non-ENOENT rc.local read errors
    tools = synthetic_env["tools_dir"]
    (tools / "openwrt-base" / "mu300-keys").write_bytes(b"KEYS")
    put_paths: list[str] = []
    with (
        patch("provision_openwrt.sftp_get_bytes", return_value=b"WRONG_SYSD_CONTENT"),
        patch("provision_openwrt.sftp_put_bytes", side_effect=lambda _s, _d, p, mode=0o644: put_paths.append(p)),
        pytest.raises(ValueError, match="Unexpected /opt/mu300/bin/mu300-sysd SHA-256"),
    ):
        _ensure_5s_buttons(MagicMock(), MagicMock(), tools_dir=tools)
    assert put_paths == []

    def _sftp_io_err(_sftp, path):
        if path == "/opt/mu300/bin/mu300-sysd":
            return b"MU300_KEYS_LONG_MS already patched"
        raise OSError(errno.EIO, "transient SFTP drop")

    with (
        patch("provision_openwrt.sftp_get_bytes", side_effect=_sftp_io_err),
        patch("provision_openwrt.sftp_put_bytes"),
        pytest.raises(OSError, match="transient SFTP drop"),
    ):
        _ensure_5s_buttons(MagicMock(), MagicMock(), tools_dir=tools)

    # 5. _set_root_password_ssh redacts passwords containing apostrophes (raw, shell-escaped, AND PTY exception __context__)
    secret = "Ultra'Secret'Pw99!"
    escaped = secret.replace("'", "'\"'\"'")
    with patch("provision_openwrt.ssh_run", side_effect=RuntimeError(f"failed cmd with '{escaped}'")):
        with pytest.raises(RuntimeError) as exc_info:
            _set_root_password_ssh(object(), secret)
    assert "Ultra" not in str(exc_info.value)
    assert "Secret" not in str(exc_info.value)
    assert "***REDACTED***" in str(exc_info.value)

    bad_pty_ssh = MagicMock()
    bad_pty_ssh.exec_command.side_effect = OSError(f"pty broke for {secret}")
    with patch("provision_openwrt.ssh_run", side_effect=RuntimeError(f"pipe cmd had {secret}")):
        with pytest.raises(RuntimeError) as pty_exc_info:
            _set_root_password_ssh(bad_pty_ssh, secret)
    assert secret not in str(pty_exc_info.value)
    assert pty_exc_info.value.__context__ is None
    assert pty_exc_info.value.__cause__ is None

    # 6. wait_for_openwrt_ssh closes SSH client if ssh_run throws inside loop
    bad_ssh = MagicMock()
    mono = iter([0.0, 0.1, 0.2, 50.0])
    with (
        patch("provision_openwrt.connect_ssh", return_value=bad_ssh),
        patch("provision_openwrt.ssh_run", side_effect=OSError("drop")),
        patch("provision_openwrt.time.monotonic", side_effect=lambda: next(mono, 99.0)),
        patch("provision_openwrt.time.sleep"),
        pytest.raises(TimeoutError),
    ):
        wait_for_openwrt_ssh("192.168.77.1", timeout=5, isolate_host=False, auto_recover_broken_ncm_serial=False)
    bad_ssh.close.assert_called()


def test_build_ota_capacity_vendor_boot_v4_and_flash_edge_cases(
    synthetic_env: dict[str, Path], tmp_path: Path
) -> None:
    """Cover real 6 MiB GPT capacity with trimmed OTA dump, vendor_boot v4 table reset, empty plan, and post-verify close."""
    # 1. Real 6 MiB GPT trustos_b with trimmed 128 KiB dump (smaller than trustos_a!) builds full 6 MiB image cleanly
    bdir = tmp_path / "ota_bak"
    shutil.copytree(synthetic_env["backup_dir"], bdir)
    xml_p = bdir / "partition_list.xml"
    xml_p.write_text(
        xml_p.read_text(encoding="utf-8").replace(
            '<Partition id="trustos_b" size="1"/>', '<Partition id="trustos_b" size="6"/>'
        ),
        encoding="utf-8",
    )
    (bdir / "trustos_b").write_bytes((bdir / "trustos_a").read_bytes()[: 128 * 1024])
    (bdir / "sml_b").write_bytes((bdir / "sml_a").read_bytes()[: 64 * 1024])
    out_ota = tmp_path / "ota_out"
    plan_ota = build_profile(
        backup_dir=bdir,
        profile_id="2-dual-stock-openwrt",
        out_dir=out_ota,
        tools_dir=synthetic_env["tools_dir"],
    )
    tos_op = next(o for o in plan_ota["operations"] if o["partition"] == "trustos_b")
    assert tos_op["size_bytes"] == 6 * 1024 * 1024

    # 2. repack_vendor_boot_v4 raises ValueError (NOT NameError), rejects undersized ent_sz, resets multi-entry table cleanly
    bad_vb = bytearray(b"VNDRBOOT" + b"\x00" * 4096)
    struct.pack_into("<I", bad_vb, 8, 3)
    with pytest.raises(ValueError, match="Expected vendor_boot v4, got 3"):
        repack_vendor_boot_v4(bytes(bad_vb), "arg=1", expected_dtb_sha256="0" * 64, ramdisk=b"ram")

    orig_vb = bytearray((synthetic_env["backup_dir"] / "vendor_boot_a").read_bytes())
    page = struct.unpack_from("<I", orig_vb, 12)[0]
    v_ram_sz = struct.unpack_from("<I", orig_vb, 24)[0]
    hdr_sz, dtb_sz, _ = struct.unpack_from("<IIQ", orig_vb, 2096)
    tbl_sz, _, tbl_ent_sz, bc_sz = struct.unpack_from("<4I", orig_vb, 2112)
    off_dtb = ((hdr_sz + page - 1) // page) * page + ((v_ram_sz + page - 1) // page) * page
    off_tbl = off_dtb + ((dtb_sz + page - 1) // page) * page
    dtb_sha = sha256_bytes(bytes(orig_vb[off_dtb : off_dtb + dtb_sz]))
    # Mark first entry as recovery type (2) + custom board_id (99) & tbl_num=2; repacked entry must be clean platform (1) & 0!
    struct.pack_into("<4I", orig_vb, off_tbl, 123, 0, 2, 99)
    struct.pack_into("<4I", orig_vb, 2112, tbl_ent_sz * 2, 2, tbl_ent_sz, bc_sz)
    repacked_vb, _ = repack_vendor_boot_v4(bytes(orig_vb), "foo=1", expected_dtb_sha256=dtb_sha, ramdisk=b"NEW_RAM")
    new_tbl_sz, new_tbl_num, new_ent_sz, _ = struct.unpack_from("<4I", repacked_vb, 2112)
    assert new_tbl_num == 1
    assert new_tbl_sz == new_ent_sz
    new_ram_sz = struct.unpack_from("<I", repacked_vb, 24)[0]
    new_off_tbl = ((hdr_sz + page - 1) // page) * page + ((new_ram_sz + page - 1) // page) * page + ((dtb_sz + page - 1) // page) * page
    ent_sz_v, ent_off_v, ent_type_v, ent_board_v = struct.unpack_from("<4I", repacked_vb, new_off_tbl)
    assert (ent_sz_v, ent_off_v, ent_type_v, ent_board_v) == (len(b"NEW_RAM"), 0, 1, 0)

    # 3. validate_plan_safety rejects empty operations
    with pytest.raises(ValueError, match="no operations"):
        validate_plan_safety({"profile": "2-dual-stock-openwrt", "operations": []})

    # 4. execute_flash keeps FLASH_AND_READBACK_VERIFIED if sess.close(reboot=True) times out
    out_close = tmp_path / "close_warn"
    plan_c = build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="1-android-ufi",
        out_dir=out_close,
        tools_dir=synthetic_env["tools_dir"],
        adb_pubkey_path=synthetic_env["adb_pubkey"],
    )
    good_tbl = list(parse_partition_xml(synthetic_env["backup_dir"] / "partition_list.xml").items())
    sess_c = MagicMock()
    sess_c.table.return_value = good_tbl
    sess_c._reset_written = True
    sess_c.close.side_effect = subprocess.TimeoutExpired(cmd="spd_dump", timeout=15)

    def _already_done(part: str, sz: int, fname: str) -> bytes:
        if "_id_probe" in fname:
            return (synthetic_env["backup_dir"] / part).read_bytes()[:sz]
        for o in plan_c["operations"]:
            if o["partition"] == part:
                return Path(o["file"]).read_bytes()[:sz]
        return b"\x00" * sz

    sess_c.read_part.side_effect = _already_done
    with patch("flash_images.resolve_tool", return_value=tmp_path / "spd_dump"), patch(
        "flash_images._SpdSession", return_value=sess_c
    ):
        res_c = execute_flash(out_close / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], execute=True)
    assert res_c["status"] == "FLASH_AND_READBACK_VERIFIED"
    assert res_c["reset_sent"] is True
    assert "close_warning" in res_c
    state_c = json.loads((out_close / "flash-run" / "flash_state.json").read_text(encoding="utf-8"))
    assert state_c["status"] == "FLASH_AND_READBACK_VERIFIED"


def test_host_network_disambiguation_snapshot_restore_and_fetch_cache_integrity(tmp_path: Path) -> None:
    """Cover empty-serial ambiguity, smart-quote PS escaping, snapshot preservation, DHCP DNS reset, tar guard, and exact cache validation."""
    # 1. Two candidates missing serial remain ambiguous even when usb_topology specifies serial
    two_no_serial = [
        {"name": "usb1", "device": "usb1", "vid": "1d6b", "pid": "0104", "serial": "", "port_path": ""},
        {"name": "usb2", "device": "usb2", "vid": "1d6b", "pid": "0104", "serial": "", "port_path": ""},
    ]
    sel = select_target_usb_adapters(two_no_serial, usb_topology={"serial": "F50-UNIT-A"})
    assert sel["ambiguous"] is True
    assert len(sel["targets"]) == 2

    # 2. PowerShell quote escaping handles both ASCII apostrophes AND typographic smart quotes safely
    assert _ps_quote("John's Ethernet") == "'John''s Ethernet'"
    smart_q = _ps_quote("Bob\u2019s F50")
    assert "FromBase64String" in smart_q and "\u2019" not in smart_q

    # 3. Initial pre-isolation snapshot is NOT overwritten on reconnects
    snap_keep = tmp_path / "keep_snap.json"
    _save_initial_snapshot(snap_keep, "192.168.77.12", [{"platform": "win64", "name": "F50", "dhcp": True}])
    _save_initial_snapshot(snap_keep, "192.168.77.12", [{"platform": "win64", "name": "F50", "dhcp": False}])
    saved_entries = json.loads(snap_keep.read_text(encoding="utf-8"))["entries"]
    assert len(saved_entries) == 1 and saved_entries[0]["dhcp"] is True

    # 4. Windows DHCP restore resets DNS instead of pinning DHCP-obtained DNS as static; static restore preserves static IP/DNS
    snap_dhcp = tmp_path / "win_dhcp_snap.json"
    snap_dhcp.write_text(
        json.dumps({
            "applied_static_ip": "192.168.77.12",
            "entries": [{
                "platform": "win64",
                "name": "Bob's F50",
                "dhcp": True,
                "ips": [{"IPAddress": "192.168.77.200", "PrefixLength": 24, "PrefixOrigin": "Dhcp"}],
                "dns": ["192.168.77.1"],
                "static_dns": [],
                "ipv6_enabled": True,
                "register_dns": True,
            }],
        }),
        encoding="utf-8",
    )
    ps_dhcp_cmds: list[str] = []
    with (
        patch("host_network._snapshot_windows_adapter", return_value={"platform": "win64", "name": "Bob's F50", "ips": [{"IPAddress": "192.168.77.12"}]}),
        patch("host_network._ps", side_effect=lambda c, **k: ps_dhcp_cmds.append(c) or '{"found":true,"errors":[]}'),
    ):
        rest_dhcp = restore_network_snapshot(snap_dhcp)
    assert rest_dhcp["results"][0]["status"] == "restored_dhcp"
    assert "-ResetServerAddresses" in ps_dhcp_cmds[0]
    assert "-ServerAddresses" not in ps_dhcp_cmds[0]

    # 5. Tar symlink escape rejected
    evil_tar = tmp_path / "evil.tar.gz"
    with tarfile.open(evil_tar, "w:gz") as tf:
        ti = tarfile.TarInfo("escape_link")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "../../outside.txt"
        tf.addfile(ti)
    with pytest.raises(ValueError):
        _safe_extract_tar(evil_tar, tmp_path / "extract_dst")

    # 6. fetch_and_extract: real manifest file (NOT globally mocked read_json!) hits cache when intact,
    #    re-extracts on deleted file, AND re-extracts & wipes rogue unverified extra APK!
    good_tar = tmp_path / "good.tar.gz"
    with tarfile.open(good_tar, "w:gz") as tf:
        data = b"TOOL_BINARY"
        ti = tarfile.TarInfo("bin/tool.bin")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    good_sha = hashlib.sha256(good_tar.read_bytes()).hexdigest()
    manifest_file = tmp_path / "manifest.json"
    manifest_file.write_text(
        json.dumps({
            "release_tag": "v1.1.0",
            "base_url": "https://example.invalid",
            "packs": {
                "host_tools_linux_x64": {
                    "filename": "good.tar.gz",
                    "sha256": good_sha,
                    "size_bytes": good_tar.stat().st_size,
                }
            },
        }),
        encoding="utf-8",
    )
    cache_d = tmp_path / "cache"
    cache_d.mkdir()
    shutil.copy2(good_tar, cache_d / "good.tar.gz")
    tools_d = tmp_path / "tools"
    with patch("fetch_assets.MANIFEST_PATH", manifest_file):
        r1 = fetch_and_extract(
            explicit_packs=["host_tools_linux_x64"], cache_dir=cache_d, tools_dir=tools_d, offline_only=True
        )
        assert r1["packs"]["host_tools_linux_x64"]["status"] == "extracted"
        # Intact cache MUST return 'cached'
        r2 = fetch_and_extract(
            explicit_packs=["host_tools_linux_x64"], cache_dir=cache_d, tools_dir=tools_d, offline_only=True
        )
        assert r2["packs"]["host_tools_linux_x64"]["status"] == "cached"
        # Deleted file MUST invalidate cache & re-extract
        extracted_tool = tools_d / "host-tools-linux-x64" / "bin" / "tool.bin"
        extracted_tool.unlink()
        r3 = fetch_and_extract(
            explicit_packs=["host_tools_linux_x64"], cache_dir=cache_d, tools_dir=tools_d, offline_only=True
        )
        assert r3["packs"]["host_tools_linux_x64"]["status"] == "extracted"
        assert extracted_tool.is_file()
        # Extra unverified rogue APK dropped into cache dir MUST invalidate cache & be wiped on re-extract
        rogue = tools_d / "host-tools-linux-x64" / "rogue.apk"
        rogue.write_bytes(b"ROGUE_APK")
        r4 = fetch_and_extract(
            explicit_packs=["host_tools_linux_x64"], cache_dir=cache_d, tools_dir=tools_d, offline_only=True
        )
        assert r4["packs"]["host_tools_linux_x64"]["status"] == "extracted"
        assert not rogue.exists()


def test_kit_verify_and_static_guards(synthetic_env: dict[str, Path], tmp_path: Path) -> None:
    """Cover --reuse-backup fail-closed (even with verification_report.json), preflight pyserial/adbkey, verify_e2e strictness."""
    # 1. --reuse-backup with missing SHA256SUMS.txt (even if verification_report.json exists) must raise FileNotFoundError
    work_no_sums = tmp_path / "work_no_sums"
    (work_no_sums / "backup").mkdir(parents=True)
    (work_no_sums / "backup" / "partition_list.xml").write_text("<Partitions/>", encoding="utf-8")
    (work_no_sums / "backup" / "verification_report.json").write_text('{"checks_passed": true}', encoding="utf-8")
    with pytest.raises(FileNotFoundError, match="--reuse-backup requested"):
        kit_main([
            "auto",
            "--profile",
            "2-dual-stock-openwrt",
            "--work-dir",
            str(work_no_sums),
            "--reuse-backup",
            "--execute",
        ])

    # 2. --usb-net-mode choices has no duplicate 'auto'
    parser = build_parser()
    sub_actions = [a for a in parser._actions if hasattr(a, "choices") and isinstance(a.choices, dict)]
    au_parser = sub_actions[0].choices["auto"]
    usb_action = next(a for a in au_parser._actions if "--usb-net-mode" in a.option_strings)
    assert list(usb_action.choices).count("auto") == 1

    # 3. win64 preflight requires 'serial' for OpenWrt AND Profile 3 provision-android, and blocks missing adbkey.pub on Android auto
    with (
        patch("kit.detect_host_platform", return_value="win64"),
        patch("kit.importlib.import_module", side_effect=lambda m: (_ for _ in ()).throw(ImportError()) if m == "serial" else MagicMock()),
        patch("kit.audit_default_routes", return_value={"usb_default_route_leak": False}),
    ):
        pre_ow = run_preflight(tools_dir=synthetic_env["tools_dir"], operation="provision-openwrt", profile="2-dual-stock-openwrt")
        pre_p3 = run_preflight(tools_dir=synthetic_env["tools_dir"], operation="provision-android", profile="3-dual-full")
    assert pre_ow["ready"] is False and "serial" in pre_ow["missing_modules"]
    assert pre_p3["ready"] is False and "serial" in pre_p3["missing_modules"]

    with (
        patch("kit.resolve_tool", return_value=tmp_path / "fake_tool"),
        patch("kit.audit_default_routes", return_value={"usb_default_route_leak": False}),
    ):
        pre_no_key = run_preflight(
            tools_dir=synthetic_env["tools_dir"],
            operation="auto",
            profile="3-dual-full",
            adb_pubkey=tmp_path / "missing_adbkey.pub",
        )
    assert pre_no_key["ready"] is False
    assert any("ADB RSA public key" in r for r in pre_no_key["blocking_reasons"])

    # 4. verify_e2e: wrong model -> FAIL; missing ip route tool -> FAIL; Profile 1 observed leak -> FAIL;
    #    Profile 1 no leak -> NOT_APPLICABLE; LuCI 403 requires luci_login_detected=True; dead OpenClash DNS -> FAIL
    ev_model = evaluate_e2e_checks(
        profile_id="2-dual-stock-openwrt",
        host_routes={"usb_default_route_leak": False},
        openwrt={"reachable": True, "model": "other-router", "active_os": "UNKNOWN", "slot_suffix": "_b", "luci_http_status": 200},
        android={"reachable": False},
    )
    assert ev_model["overall_status"] == "FAIL"
    assert ev_model["checks"]["openwrt_ssh"]["status"] == "FAIL"

    ev_no_ip = evaluate_e2e_checks(
        profile_id="2-dual-stock-openwrt",
        host_routes={"usb_default_route_leak": False, "audit_incomplete": True, "warning": "ip command missing"},
        openwrt={"reachable": True, "model": "f50pro", "active_os": "openwrt", "slot_suffix": "_b", "luci_http_status": 403, "luci_login_detected": True},
        android={"reachable": False},
    )
    assert ev_no_ip["checks"]["host_route_isolation"]["status"] == "FAIL"
    assert ev_no_ip["checks"]["openwrt_luci"]["status"] == "PASS"

    ev_403_bad = evaluate_e2e_checks(
        profile_id="2-dual-stock-openwrt",
        host_routes={"usb_default_route_leak": False},
        openwrt={"reachable": True, "model": "f50pro", "active_os": "openwrt", "slot_suffix": "_b", "luci_http_status": 403, "luci_login_detected": False},
        android={"reachable": False},
    )
    assert ev_403_bad["checks"]["openwrt_luci"]["status"] == "FAIL"

    ev_p1_leak = evaluate_e2e_checks(
        profile_id="1-android-ufi",
        host_routes={"usb_default_route_leak": True},
        openwrt={"reachable": False},
        android={"reachable": True, "slot_suffix": "_a", "su_id": "0", "ports": ":2333 :1146"},
    )
    assert ev_p1_leak["checks"]["host_route_isolation"]["status"] == "FAIL"
    assert ev_p1_leak["overall_status"] == "FAIL"

    ev_p1_clean = evaluate_e2e_checks(
        profile_id="1-android-ufi",
        host_routes={"usb_default_route_leak": False},
        openwrt={"reachable": False},
        android={"reachable": True, "slot_suffix": "_a", "su_id": "0", "ports": ":2333 :1146"},
    )
    assert ev_p1_clean["checks"]["host_route_isolation"]["status"] == "NOT_APPLICABLE"
    assert ev_p1_clean["overall_status"] == "PASS"

    ev_oc_dns = evaluate_e2e_checks(
        profile_id="2-dual-stock-openwrt",
        host_routes={"usb_default_route_leak": False},
        openwrt={
            "reachable": True,
            "model": "f50pro",
            "active_os": "openwrt",
            "slot_suffix": "_b",
            "luci_http_status": 200,
            "openclash_9090_listening": True,
            "openclash_dns_ok": False,
        },
        android={"reachable": False},
        check_openclash=True,
    )
    assert ev_oc_dns["checks"]["openclash_9090"]["status"] == "FAIL"

    # 5. .gitignore, bootstrap.ps1, and recovery doc CLI checks
    gitignore_txt = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "*credentials*.json" in gitignore_txt
    ps1_txt = (REPO_ROOT / "scripts" / "bootstrap.ps1").read_text(encoding="utf-8")
    assert "$LASTEXITCODE -ne 0" in ps1_txt
    rec_doc = (REPO_ROOT / "docs" / "recovery-and-safety.md").read_text(encoding="utf-8")
    assert "bind-rndis --install" not in rec_doc


def test_round2_hardening_gates(synthetic_env: dict[str, Path], tmp_path: Path) -> None:
    """Cover Round-2 gates: mandatory backup manifest on flash/stage, pre-write baseline check, empty boot_id/ps/wildcard ttyd rejection, Linux IPv4 leak + IPv6 fail."""
    from host_network import audit_default_routes

    # 1. execute_flash and apply_slot_a_from_openwrt refuse plans missing backup_sha256sums_sha256
    out_nom = tmp_path / "nom"
    plan_nom = build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="3-dual-full",
        out_dir=out_nom,
        tools_dir=synthetic_env["tools_dir"],
        adb_pubkey_path=synthetic_env["adb_pubkey"],
    )
    plan_nom["backup_sha256sums_sha256"] = None
    (out_nom / "flash_plan.json").write_text(json.dumps(plan_nom), encoding="utf-8")
    with pytest.raises(ValueError, match="backup_sha256sums_sha256"):
        execute_flash(out_nom / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], execute=True)
    with pytest.raises(ValueError, match="backup_sha256sums_sha256"):
        apply_slot_a_from_openwrt(plan_nom, isolate_host=False)

    # 2. execute_flash refuses overwriting live partition that differs from verified backup baseline (unless allow_dirty_target=True)
    out_dirty = tmp_path / "dirty"
    plan_dirty = build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="1-android-ufi",
        out_dir=out_dirty,
        tools_dir=synthetic_env["tools_dir"],
        adb_pubkey_path=synthetic_env["adb_pubkey"],
    )
    good_tbl = list(parse_partition_xml(synthetic_env["backup_dir"] / "partition_list.xml").items())
    sess_d = MagicMock()
    sess_d.table.return_value = good_tbl

    def _dirty_read(part: str, sz: int, fname: str) -> bytes:
        if "_id_probe" in fname:
            return (synthetic_env["backup_dir"] / part).read_bytes()[:sz]
        return b"\xdd" * sz  # unexpected live state != backup and != replacement

    sess_d.read_part.side_effect = _dirty_read
    with patch("flash_images.resolve_tool", return_value=tmp_path / "spd_dump"), patch(
        "flash_images._SpdSession", return_value=sess_d
    ):
        with pytest.raises(RuntimeError, match="differs from verified backup baseline"):
            execute_flash(out_dirty / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], execute=True)
    sess_d.cmd.assert_not_called()

    # 3. provision_android rejects wrong-unit ADB device, empty boot_id, empty ps / wildcard / cellular interface / non-ttyd binary
    (synthetic_env["tools_dir"] / "openwrt-base" / "mu300-keys").write_bytes(b"KEYS")
    out_p3 = tmp_path / "p3_strict"
    plan_p3 = build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="3-dual-full",
        out_dir=out_p3,
        tools_dir=synthetic_env["tools_dir"],
        adb_pubkey_path=synthetic_env["adb_pubkey"],
    )

    def _p3_id_reply(script: str) -> str | None:
        ident = plan_p3["device_identity"]
        if "board_id" in script:
            return f"{ident.get('board_id', '6')}\n"
        for pname, pspec in (ident.get("unit_identity_partitions") or {}).items():
            if f"/dev/block/by-name/{pname}" in script:
                return f"{pspec['sha256']}\n"
        if "/dev/block/by-name/vendor_boot_a" in script:
            return f"{ident['firmware_build']['vendor_boot_a_sha256']}\n"
        return None

    # Wrong-unit Android ADB device must abort BEFORE pushing any APK or known-good-b-bcab.bin
    adb_wrong_calls: list[str] = []
    with (
        patch("provision_android.resolve_tool", return_value=tmp_path / "adb"),
        patch("provision_android.apply_slot_a_from_openwrt", return_value={}),
        patch("provision_android.wait_for_adb_slot_a", return_value="_a"),
        patch("provision_android._adb", side_effect=lambda _e, a, **k: adb_wrong_calls.append(" ".join(a)) or ""),
        patch("provision_android._su", side_effect=lambda _e, s, **k: "6\n" if "board_id" in s else "e" * 64 + "\n"),
        pytest.raises(RuntimeError, match="Target device identity mismatch on Android ADB"),
    ):
        provision_android(plan_path=out_p3 / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], return_to_openwrt=False)
    assert not any("install" in c or "known-good-b-bcab" in c for c in adb_wrong_calls)

    with (
        patch("provision_android.resolve_tool", return_value=tmp_path / "adb"),
        patch("provision_android.apply_slot_a_from_openwrt", return_value={}),
        patch("provision_android.wait_for_adb_slot_a", return_value="_a"),
        patch(
            "provision_android._adb",
            side_effect=lambda _e, a, **k: ""
            if "boot_id" in " ".join(a)
            else ("package:com.minikano.f50_sms uid:10234\n" if "pm list" in " ".join(a) else ""),
        ),
        patch("provision_android._su", side_effect=lambda _e, s, **k: _p3_id_reply(s) or ""),
        patch("provision_android.time.sleep"),
        pytest.raises(RuntimeError, match="invalid or unchanged /proc/sys/kernel/random/boot_id"),
    ):
        provision_android(plan_path=out_p3 / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], return_to_openwrt=False)

    # Empty ps or wildcard 0.0.0.0:1146 or non-UUID boot_ids or split-process ttyd must NOT pass hardened verification
    bids = iter(["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"])
    mono_t = iter([0.0, 1.0, 200.0])
    with (
        patch("provision_android.resolve_tool", return_value=tmp_path / "adb"),
        patch("provision_android.apply_slot_a_from_openwrt", return_value={}),
        patch("provision_android.wait_for_adb_slot_a", return_value="_a"),
        patch(
            "provision_android._adb",
            side_effect=lambda _e, a, **k: next(bids)
            if "boot_id" in " ".join(a)
            else ("package:com.minikano.f50_sms uid:10234\n" if "pm list" in " ".join(a) else ""),
        ),
        patch(
            "provision_android._su",
            side_effect=lambda _e, s, **k: _p3_id_reply(s)
            if _p3_id_reply(s) is not None
            else ("LISTEN 0 128 0.0.0.0:2333 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:1146 0.0.0.0:*\n" if "ss -tln" in s else ""),
        ),
        patch("provision_android.time.monotonic", side_effect=lambda: next(mono_t, 999.0)),
        patch("provision_android.time.sleep"),
        pytest.raises(RuntimeError, match="hardened bound ttyd"),
    ):
        provision_android(plan_path=out_p3 / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], return_to_openwrt=False)

    # Non-UUID arbitrary boot_id strings must be rejected
    bids_bad = iter(["arbitrary-a", "arbitrary-b"])
    with (
        patch("provision_android.resolve_tool", return_value=tmp_path / "adb"),
        patch("provision_android.apply_slot_a_from_openwrt", return_value={}),
        patch("provision_android.wait_for_adb_slot_a", return_value="_a"),
        patch(
            "provision_android._adb",
            side_effect=lambda _e, a, **k: next(bids_bad)
            if "boot_id" in " ".join(a)
            else ("package:com.minikano.f50_sms uid:10234\n" if "pm list" in " ".join(a) else ""),
        ),
        patch("provision_android._su", side_effect=lambda _e, s, **k: _p3_id_reply(s) or ""),
        patch("provision_android.time.sleep"),
        pytest.raises(RuntimeError, match="invalid or unchanged /proc/sys/kernel/random/boot_id"),
    ):
        provision_android(plan_path=out_p3 / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], return_to_openwrt=False)

    # Strict manifest requires partition_list.xml entry; trimmed backup still records expected_before_sha256; PTY backslash password redacted
    bdir_no_xml_entry = tmp_path / "bak_no_xml_entry"
    shutil.copytree(synthetic_env["backup_dir"], bdir_no_xml_entry)
    sums_lines_no_xml = [
        ln for ln in (bdir_no_xml_entry / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
        if not ln.endswith("  partition_list.xml")
    ]
    (bdir_no_xml_entry / "SHA256SUMS.txt").write_text("\n".join(sums_lines_no_xml) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="partition_list.xml is missing from existing SHA256SUMS.txt"):
        verify_backup_dir(bdir_no_xml_entry, require_complete_table=True, require_existing_manifest=True)

    # Backslash password in PTY output must be redacted BEFORE repr() escaping
    bs_secret = r"Pass\Word\99!"
    pty_ssh_bs = MagicMock()
    st_in, st_out, st_err = MagicMock(), MagicMock(), MagicMock()
    st_out.channel.recv_exit_status.return_value = 1
    st_out.read.return_value = f"echoed {bs_secret}\n".encode("utf-8")
    st_err.read.return_value = b""
    pty_ssh_bs.exec_command.return_value = (st_in, st_out, st_err)
    with patch("provision_openwrt.ssh_run", side_effect=RuntimeError("pipe fail")), patch("provision_openwrt.time.sleep"):
        with pytest.raises(RuntimeError) as bs_exc:
            _set_root_password_ssh(pty_ssh_bs, bs_secret)
    assert "Pass" not in str(bs_exc.value) and "Word" not in str(bs_exc.value)
    assert "***REDACTED***" in str(bs_exc.value)

    # 4. Linux audit_default_routes preserves IPv4 USB default-route leak even when IPv6 query fails
    r4_ok = subprocess.CompletedProcess(["ip"], 0, stdout=json.dumps([{"dst": "default", "dev": "usb0", "gateway": "192.168.77.1"}]), stderr="")
    r6_err = subprocess.CompletedProcess(["ip"], 1, stdout="", stderr="ipv6 disabled")
    with (
        patch("host_network.sys.platform", "linux"),
        patch("host_network.detect_host_platform", return_value="linux-x64"),
        patch("host_network._detect_linux_net_candidates", return_value=[{"name": "usb0", "vid": "1d6b", "pid": "0104", "serial": "s1", "port_path": "1-1"}]),
        patch("host_network.shutil.which", return_value="/usr/sbin/ip"),
        patch("host_network._run_cmd", side_effect=[r4_ok, r6_err]),
    ):
        aud = audit_default_routes()
    assert aud["usb_default_route_leak"] is True
    assert aud["audit_incomplete"] is True

    # 5. Round-4 micro-fixes: macOS netstat failure marks audit_incomplete; symlink inside cache invalidates cache;
    #    :::1146 wildcard rejected; invalid UUID version/variant rejected; matching wof bytes skip redundant wof write
    r_err = subprocess.CompletedProcess(["netstat"], 1, stdout="", stderr="err")
    with (
        patch("host_network.sys.platform", "darwin"),
        patch("host_network.detect_host_platform", return_value="macos"),
        patch("host_network._detect_macos_candidates", return_value=[]),
        patch("host_network._run_cmd", side_effect=[r_err, r_err]),
    ):
        mac_aud = audit_default_routes()
    assert mac_aud["audit_incomplete"] is True

    # Invalid RFC-4122 UUID version/variant bits in boot_id must be rejected
    bad_ver_bids = iter(["11111111-1111-9111-8111-111111111111", "22222222-2222-4222-0222-222222222222"])
    with (
        patch("provision_android.resolve_tool", return_value=tmp_path / "adb"),
        patch("provision_android.apply_slot_a_from_openwrt", return_value={}),
        patch("provision_android.wait_for_adb_slot_a", return_value="_a"),
        patch(
            "provision_android._adb",
            side_effect=lambda _e, a, **k: next(bad_ver_bids)
            if "boot_id" in " ".join(a)
            else ("package:com.minikano.f50_sms uid:10234\n" if "pm list" in " ".join(a) else ""),
        ),
        patch("provision_android._su", side_effect=lambda _e, s, **k: _p3_id_reply(s) or ""),
        patch("provision_android.time.sleep"),
        pytest.raises(RuntimeError, match="invalid or unchanged /proc/sys/kernel/random/boot_id"),
    ):
        provision_android(plan_path=out_p3 / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], return_to_openwrt=False)

    # :::1146 wildcard listener and multi-PID partial match must be rejected
    bids_wc = iter(["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"])
    mono_wc = iter([0.0, 1.0, 200.0])
    with (
        patch("provision_android.resolve_tool", return_value=tmp_path / "adb"),
        patch("provision_android.apply_slot_a_from_openwrt", return_value={}),
        patch("provision_android.wait_for_adb_slot_a", return_value="_a"),
        patch(
            "provision_android._adb",
            side_effect=lambda _e, a, **k: next(bids_wc)
            if "boot_id" in " ".join(a)
            else ("package:com.minikano.f50_sms uid:10234\n" if "pm list" in " ".join(a) else ""),
        ),
        patch(
            "provision_android._su",
            side_effect=lambda _e, s, **k: _p3_id_reply(s)
            if _p3_id_reply(s) is not None
            else (
                "LISTEN 0 128 0.0.0.0:2333 0.0.0.0:*\nLISTEN 0 128 :::1146 :::*\n"
                if "ss -tln" in s
                else "root 999 1 0 ttyd --writable --port 1146 --interface br0 /data/adb/ufi-ttyd-login.sh\n"
            ),
        ),
        patch("provision_android.time.monotonic", side_effect=lambda: next(mono_wc, 999.0)),
        patch("provision_android.time.sleep"),
        pytest.raises(RuntimeError, match="hardened bound ttyd"),
    ):
        provision_android(plan_path=out_p3 / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], return_to_openwrt=False)

    # Matching wof slice treats offset write as already_verified no-op (never issues redundant wof)
    out_wof = tmp_path / "wof_noop"
    plan_w = build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="2-dual-stock-openwrt",
        out_dir=out_wof,
        tools_dir=synthetic_env["tools_dir"],
    )
    wof_only = [o for o in plan_w["operations"] if o["op"] == "wof"]
    plan_w["operations"] = wof_only
    (out_wof / "flash_plan.json").write_text(json.dumps(plan_w), encoding="utf-8")
    trial_data = Path(wof_only[0]["file"]).read_bytes()
    already_misc = bytearray((synthetic_env["backup_dir"] / "misc").read_bytes())
    already_misc[2048 : 2048 + 32] = trial_data
    sess_w = MagicMock()
    sess_w.table.return_value = good_tbl
    sess_w._reset_written = True
    sess_w.read_part.side_effect = lambda p, sz, fn: (
        (synthetic_env["backup_dir"] / p).read_bytes()[:sz] if "_id_probe" in fn else bytes(already_misc[:sz])
    )
    with patch("flash_images.resolve_tool", return_value=tmp_path / "spd_dump"), patch(
        "flash_images._SpdSession", return_value=sess_w
    ):
        res_w = execute_flash(out_wof / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], execute=True)
    assert res_w["results"]["misc+2048"]["method"] == "already_verified"
    sess_w.cmd.assert_not_called()

    # Windows audit_default_routes sets audit_incomplete when query_errors non-empty, clean when empty
    with (
        patch("host_network.sys.platform", "win32"),
        patch(
            "host_network._ps",
            return_value='{"ipv4_default":[],"ipv6_default":[],"rndis_adapters":[],"query_errors":["routes:CIM failure"]}',
        ),
    ):
        win_err_aud = audit_default_routes()
    assert win_err_aud["audit_incomplete"] is True

    # Listener PID matching requires column 2 (PID), NOT column 3 (PPID), AND rejects cellular interface / non-ttyd binary
    for bad_ps in (
        "root 200 100 0 ttyd --writable --port 1146 --interface br0 /data/adb/ufi-ttyd-login.sh\n",
        "root 100 1 0 ttyd --writable --port 1146 --interface seth_lte0 /data/adb/ufi-ttyd-login.sh\n",
        "root 100 1 0 /bin/evil --arg ttyd --writable --port 1146 --interface br0 /data/adb/ufi-ttyd-login.sh\n",
    ):
        bids_ppid = iter(["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"])
        mono_ppid = iter([0.0, 1.0, 200.0])
        with (
            patch("provision_android.resolve_tool", return_value=tmp_path / "adb"),
            patch("provision_android.apply_slot_a_from_openwrt", return_value={}),
            patch("provision_android.wait_for_adb_slot_a", return_value="_a"),
            patch(
                "provision_android._adb",
                side_effect=lambda _e, a, **k: next(bids_ppid)
                if "boot_id" in " ".join(a)
                else ("package:com.minikano.f50_sms uid:10234\n" if "pm list" in " ".join(a) else ""),
            ),
            patch(
                "provision_android._su",
                side_effect=lambda _e, s, bps=bad_ps, **k: _p3_id_reply(s)
                if _p3_id_reply(s) is not None
                else (
                    'LISTEN 0 128 192.168.0.1:2333 0.0.0.0:*\nLISTEN 0 128 192.168.0.1:1146 0.0.0.0:* users:(("ttyd",pid=100,fd=3))\n'
                    if "ss -tln" in s
                    else bps
                ),
            ),
            patch("provision_android.time.monotonic", side_effect=lambda: next(mono_ppid, 999.0)),
            patch("provision_android.time.sleep"),
            pytest.raises(RuntimeError, match="hardened bound ttyd"),
        ):
            provision_android(plan_path=out_p3 / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], return_to_openwrt=False)

    # Extracted cache validator rejects symlinks on root, metadata, or files; OpenClash rejects symlinked pack root
    from fetch_assets import _is_extracted_cache_valid

    sym_dir = tmp_path / "sym_cache"
    sym_dir.mkdir()
    ok_f = sym_dir / "ok.bin"
    ok_f.write_bytes(b"OK")
    (sym_dir / ".verified.sha256").write_text("a" * 64 + "\n", encoding="utf-8")
    (sym_dir / ".verified.manifest.json").write_text(
        json.dumps({"archive_sha256": "a" * 64, "files": {"ok.bin": {"size": 2, "sha256": sha256_bytes(b"OK")}}}),
        encoding="utf-8",
    )
    assert _is_extracted_cache_valid(sym_dir, "a" * 64) is True
    for bad_name in ("ok.bin", "sym_cache", ".verified.sha256", ".verified.manifest.json"):
        with patch.object(Path, "is_symlink", side_effect=lambda self, bn=bad_name: self.name == bn, autospec=True):
            assert _is_extracted_cache_valid(sym_dir, "a" * 64) is False

    # OpenClash offline installer rejects symlinked openclash-offline root directory
    from provision_openwrt import _install_openclash_offline

    with patch.object(Path, "is_symlink", side_effect=lambda self: self.name == "openclash-offline", autospec=True):
        with pytest.raises(ValueError, match="symlinked/junction OpenClash offline directory"):
            _install_openclash_offline(MagicMock(), MagicMock(), tools_dir=synthetic_env["tools_dir"])

    # Unattributed :1146 listener (no PID from ss/netstat) must NOT disarm rollback even if hardened ttyd appears in ps
    bids_nopid = iter(["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"])
    mono_nopid = iter([0.0, 1.0, 200.0])
    with (
        patch("provision_android.resolve_tool", return_value=tmp_path / "adb"),
        patch("provision_android.apply_slot_a_from_openwrt", return_value={}),
        patch("provision_android.wait_for_adb_slot_a", return_value="_a"),
        patch(
            "provision_android._adb",
            side_effect=lambda _e, a, **k: next(bids_nopid)
            if "boot_id" in " ".join(a)
            else ("package:com.minikano.f50_sms uid:10234\n" if "pm list" in " ".join(a) else ""),
        ),
        patch(
            "provision_android._su",
            side_effect=lambda _e, s, **k: _p3_id_reply(s)
            if _p3_id_reply(s) is not None
            else (
                "LISTEN 0 128 192.168.0.1:2333 0.0.0.0:*\nLISTEN 0 128 192.168.0.1:1146 0.0.0.0:*\n"
                if "ss -tln" in s
                else "root 999 1 0 ttyd --writable --port 1146 --interface br0 /data/adb/ufi-ttyd-login.sh\n"
            ),
        ),
        patch("provision_android.time.monotonic", side_effect=lambda: next(mono_nopid, 999.0)),
        patch("provision_android.time.sleep"),
        pytest.raises(RuntimeError, match="hardened bound ttyd"),
    ):
        provision_android(plan_path=out_p3 / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], return_to_openwrt=False)

    # Windows isolate_usb_rndis_adapter rejects incomplete route audit & attaches audit field
    from host_network import isolate_usb_rndis_adapter

    with (
        patch("host_network.detect_host_platform", return_value="win64"),
        patch("host_network._snapshot_windows_adapter", return_value={"platform": "win64", "name": "F50"}),
        patch(
            "host_network._ps",
            side_effect=[
                json.dumps([{"name": "F50", "ifIndex": 7, "vid": "1d6b", "pid": "0104", "pnp_id": "USB\\VID_1D6B&PID_0104\\1", "serial": "s1"}]),
                json.dumps({"isolated": [{"name": "F50", "ifIndex": 7}], "target_default_routes": [], "query_errors": []}),
            ],
        ),
        patch("host_network.audit_default_routes", return_value={"usb_default_route_leak": False, "audit_incomplete": True}),
    ):
        with pytest.raises(RuntimeError, match="incomplete route audit"):
            isolate_usb_rndis_adapter(snapshot_path=tmp_path / "win_iso_snap.json")

    # kit.py auto --reuse-backup --resume requires matching flash_result.json AND flash_state.json;
    # stale flash_result.json with FLASH_FAILED flash_state.json MUST NOT resume; matching pair resumes cleanly
    # and passes plan_path + credentials_file to provision_openwrt!
    work_res = tmp_path / "work_resume"
    bak_res = work_res / "backup"
    shutil.copytree(synthetic_env["backup_dir"], bak_res)
    out_res = work_res / "build"
    plan_res1 = build_profile(
        backup_dir=bak_res,
        profile_id="3-dual-full",
        out_dir=out_res,
        tools_dir=synthetic_env["tools_dir"],
        adb_pubkey_path=synthetic_env["adb_pubkey"],
    )
    plan_res_sha = hashlib.sha256((out_res / "flash_plan.json").read_bytes()).hexdigest()
    (out_res / "flash-run").mkdir(parents=True, exist_ok=True)
    ok_flash_rec = {
        "status": "FLASH_AND_READBACK_VERIFIED",
        "reset_sent": True,
        "profile": "3-dual-full",
        "backup_sha256sums_sha256": plan_res1["backup_sha256sums_sha256"],
        "plan_sha256": plan_res_sha,
        "device_mutated": True,
    }
    (out_res / "flash-run" / "flash_result.json").write_text(json.dumps(ok_flash_rec), encoding="utf-8")
    (out_res / "flash-run" / "flash_state.json").write_text(json.dumps({"status": "FLASH_FAILED"}), encoding="utf-8")
    with (
        patch("kit.fetch_and_extract", return_value={"status": "cached"}),
        patch("kit.run_preflight", return_value={"ready": True, "blocking_reasons": []}),
        patch("kit.execute_flash", side_effect=RuntimeError("expected_reflash_on_stale")) as mock_exec_stale,
    ):
        with pytest.raises(RuntimeError, match="expected_reflash_on_stale"):
            kit_main([
                "auto",
                "--profile",
                "3-dual-full",
                "--work-dir",
                str(work_res),
                "--tools-dir",
                str(synthetic_env["tools_dir"]),
                "--adb-pubkey",
                str(synthetic_env["adb_pubkey"]),
                "--reuse-backup",
                "--resume",
                "--execute",
            ])
    mock_exec_stale.assert_called_once()

    # Now both flash_result.json AND flash_state.json match -> resume skips BROM flash AND passes plan_path + credentials_file
    (out_res / "flash-run" / "flash_state.json").write_text(json.dumps(ok_flash_rec), encoding="utf-8")
    with (
        patch("kit.fetch_and_extract", return_value={"status": "cached"}),
        patch("kit.run_preflight", return_value={"ready": True, "blocking_reasons": []}),
        patch("kit.execute_flash") as mock_exec_flash,
        patch("kit.provision_openwrt", return_value={"status": "ok"}) as mock_prov_ow,
        patch("kit.provision_android", return_value={"status": "ok"}),
        patch("kit.verify_environment", return_value={"overall_status": "PASS"}),
    ):
        rc_res = kit_main([
            "auto",
            "--profile",
            "3-dual-full",
            "--work-dir",
            str(work_res),
            "--tools-dir",
            str(synthetic_env["tools_dir"]),
            "--adb-pubkey",
            str(synthetic_env["adb_pubkey"]),
            "--reuse-backup",
            "--resume",
            "--execute",
        ])
    assert rc_res == 0
    mock_exec_flash.assert_not_called()
    assert mock_prov_ow.call_args.kwargs["plan_path"] == out_res / "flash_plan.json"
    assert mock_prov_ow.call_args.kwargs["credentials_file"] == out_res / "openwrt-credentials.json"
    auto_rep = json.loads((work_res / "auto_execution_report.json").read_text(encoding="utf-8"))
    assert auto_rep["brom_session_mode"] == "resumed_after_verified_flash"

    # provision_openwrt uses saved openwrt-credentials.json on retry AND verifies target identity BEFORE mu300-next-boot linux!
    saved_cred_dir = tmp_path / "retry_cred_ow"
    saved_cred_dir.mkdir()
    (saved_cred_dir / "openwrt-credentials.json").write_text(
        json.dumps({"host": "192.168.77.1", "username": "root", "password": "SavedStrongRetryPassword!"}),
        encoding="utf-8",
    )
    seen_pws: list[tuple[str, ...]] = []
    ow_cmds: list[str] = []

    def _capture_wait(_host, *, passwords=(), **kwargs):
        seen_pws.append(tuple(passwords))
        return MagicMock()

    def _wrong_unit_ssh(_ssh, cmd, **kwargs):
        ow_cmds.append(cmd)
        if "board_id" in cmd:
            return (0, "6\n", "")
        if "ztecfg" in cmd or "persist" in cmd:
            return (0, "f" * 64 + "\n", "")  # wrong unit digest!
        return (0, "usb_mode=ncm\nboard_id=6\n", "")

    with (
        patch("provision_openwrt.detect_host_platform", return_value="linux-x64"),
        patch("provision_openwrt.wait_for_openwrt_ssh", side_effect=_capture_wait),
        patch("provision_openwrt.ssh_run", side_effect=_wrong_unit_ssh),
    ):
        with pytest.raises(RuntimeError, match="Target device identity mismatch on OpenWrt"):
            provision_openwrt(
                profile_id="3-dual-full",
                out_dir=saved_cred_dir,
                generate_password=True,
                isolate_host=False,
                plan_path=out_res / "flash_plan.json",
            )
    assert "SavedStrongRetryPassword!" in seen_pws[0]
    assert not any("mu300-next-boot" in c for c in ow_cmds)

    # 6. Round-6 regressions:
    # (a) Real execute_flash() unlinks stale flash_result.json even on early backup/plan validation failure
    stale_out = tmp_path / "stale_unlink"
    plan_st = build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="1-android-ufi",
        out_dir=stale_out,
        tools_dir=synthetic_env["tools_dir"],
        adb_pubkey_path=synthetic_env["adb_pubkey"],
    )
    stale_res_f = stale_out / "flash-run" / "flash_result.json"
    stale_res_f.parent.mkdir(parents=True, exist_ok=True)
    stale_res_f.write_text('{"status":"FLASH_AND_READBACK_VERIFIED","reset_sent":true}', encoding="utf-8")
    plan_st["backup_sha256sums_sha256"] = "0" * 64
    (stale_out / "flash_plan.json").write_text(json.dumps(plan_st), encoding="utf-8")
    with pytest.raises(ValueError, match="changed after flash_plan.json was built"):
        execute_flash(stale_out / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], execute=True)
    assert not stale_res_f.exists()

    # (b) Stale --target-iface on Windows audit_default_routes still catches active F50 Pro USB default-route leak
    with (
        patch("host_network.sys.platform", "win32"),
        patch(
            "host_network._ps",
            return_value=json.dumps({
                "ipv4_default": [{"ifIndex": 9, "InterfaceAlias": "Ethernet 4", "NextHop": "192.168.77.1", "RouteMetric": 10}],
                "ipv6_default": [],
                "rndis_adapters": [{"ifIndex": 9, "Name": "Ethernet 4", "PnpDeviceID": "USB\\VID_1D6B&PID_0104\\1", "Status": "Up"}],
                "query_errors": [],
            }),
        ),
    ):
        stale_iface_aud = audit_default_routes(target_iface="Ethernet 3")
    assert stale_iface_aud["usb_default_route_leak"] is True
    assert stale_iface_aud["target_iface_not_found"] == "Ethernet 3"

    # (c) Windows NTFS junction / FILE_ATTRIBUTE_REPARSE_POINT rejected by is_link_or_reparse() & cache validator
    from common import is_link_or_reparse

    fake_st = MagicMock()
    fake_st.st_file_attributes = 0x410  # FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT
    with patch("common.os.name", "nt"), patch("common.os.lstat", return_value=fake_st):
        assert is_link_or_reparse(sym_dir) is True
        assert _is_extracted_cache_valid(sym_dir, "a" * 64) is False

    # (d) Default AuthContext does NOT push ("", "root") ahead of saved credentials_file, AND rotated password persists to explicit credentials_file!
    from common import resolve_auth_context

    explicit_cred_f = tmp_path / "custom_creds" / "my-creds.json"
    explicit_cred_f.parent.mkdir(parents=True)
    explicit_cred_f.write_text(
        json.dumps({"host": "192.168.77.1", "username": "root", "password": "PriorRotatedPassword!"}),
        encoding="utf-8",
    )
    out_rot = tmp_path / "out_rot_ok"
    default_ctx = resolve_auth_context(host="192.168.77.1")
    seen_order: list[tuple[str, ...]] = []
    valid_bcab = (synthetic_env["backup_dir"] / "misc").read_bytes()[2048 : 2048 + 32]
    from common import build_trial_bcab

    b_bcab = build_trial_bcab(valid_bcab, "b", tries=6)
    with (
        patch("provision_openwrt.detect_host_platform", return_value="linux-x64"),
        patch("provision_openwrt.wait_for_openwrt_ssh", side_effect=lambda _h, *, passwords=(), **k: seen_order.append(tuple(passwords)) or MagicMock()),
        patch("provision_openwrt._probe_remote_identity_and_usb_mode", return_value={"board_id": "6", "usb_mode": "ncm", "host_hash": "abc"}),
        patch("provision_openwrt.open_remote_fs", return_value=MagicMock()),
        patch("provision_openwrt._ensure_rootfs_grown", return_value={"status": "ok"}),
        patch("provision_openwrt._ensure_board6_card_patch", return_value="sha"),
        patch("provision_openwrt._ensure_capacity_ui", return_value={"status": "ok"}),
        patch("provision_openwrt._ensure_5s_buttons", return_value={"status": "ok"}),
        patch("provision_openwrt.ssh_run", return_value=(0, "", "")),
        patch("provision_openwrt._set_root_password_ssh") as mock_set_pw,
        patch("provision_openwrt.sftp_get_bytes", return_value=b_bcab),
    ):
        prov_rot = provision_openwrt(
            profile_id="2-dual-stock-openwrt",
            root_password="BrandNewRotatedPassword!",
            auth_context=default_ctx,
            credentials_file=explicit_cred_f,
            out_dir=out_rot,
            isolate_host=False,
            reboot_after=False,
        )
    assert seen_order[0][:2] == ("BrandNewRotatedPassword!", "PriorRotatedPassword!")
    assert seen_order[0].index("PriorRotatedPassword!") < seen_order[0].index("")
    mock_set_pw.assert_called_once()
    assert json.loads(explicit_cred_f.read_text(encoding="utf-8"))["password"] == "BrandNewRotatedPassword!"
    assert json.loads((out_rot / "openwrt-credentials.json").read_text(encoding="utf-8"))["password"] == "BrandNewRotatedPassword!"
    assert prov_rot["credentials_file"] == str(explicit_cred_f)

    # (e) Windows serial recovery refuses wrong unit BEFORE mu300-next-boot linux or device-usb set-net rndis
    from provision_openwrt import _recover_broken_ncm_via_serial

    serial_written: list[str] = []

    class _FakeSer:
        def __init__(self, *a, **k):
            self._buf = b"root@F50Pro:~# "

        @property
        def in_waiting(self) -> int:
            return len(self._buf)

        def reset_input_buffer(self) -> None:
            self._buf = b""

        def flush(self) -> None:
            pass

        def close(self) -> None:
            pass

        def write(self, data: bytes) -> int:
            txt = data.decode("utf-8", "replace")
            serial_written.append(txt)
            m = re.search(r"echo (__F50SER_[0-9a-f]+__)_B; (.*?); echo \1_E:\$\?", txt)
            if m:
                tag, cmd = m.group(1), m.group(2)
                if "/etc/mu300/model" in cmd:
                    body = "f50pro\n"
                elif "board_id" in cmd:
                    body = "6\n"
                else:
                    body = "0" * 64 + "\n"  # wrong unit digest
                self._buf = f"{tag}_B\n{body}{tag}_E:0\n".encode("utf-8")
            return len(data)

        def read(self, n: int = 1) -> bytes:
            out_b, self._buf = self._buf[:n], self._buf[n:]
            return out_b

    fake_serial_mod = MagicMock()
    fake_serial_mod.Serial.side_effect = _FakeSer
    with patch.dict("sys.modules", {"serial": fake_serial_mod}):
        with pytest.raises(RuntimeError, match="Target device identity mismatch on OpenWrt serial recovery"):
            _recover_broken_ncm_via_serial("COM9", expected_plan=plan_res1)
    assert not any("mu300-next-boot" in w or "device-usb set-net" in w for w in serial_written)

    # 7. Round-7 regressions:
    # (a) Disarmed rollback_token forces a fresh token on next build_profile() so an old marker cannot suppress rollback
    out_dis = tmp_path / "disarmed_tok"
    p_dis1 = build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="3-dual-full",
        out_dir=out_dis,
        tools_dir=synthetic_env["tools_dir"],
        adb_pubkey_path=synthetic_env["adb_pubkey"],
    )
    tok1 = p_dis1["android_a_stage"]["rollback_token"]
    (out_dis / ".rollback_token_disarmed").write_text(tok1 + "\n", encoding="utf-8")
    p_dis2 = build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="3-dual-full",
        out_dir=out_dis,
        tools_dir=synthetic_env["tools_dir"],
        adb_pubkey_path=synthetic_env["adb_pubkey"],
    )
    assert p_dis2["android_a_stage"]["rollback_token"] != tok1

    # (b) Malformed flash_plan.json still unlinks stale sibling flash_result.json before raising JSONDecodeError
    bad_plan_dir = tmp_path / "malformed_plan"
    bad_plan_f = bad_plan_dir / "flash_plan.json"
    bad_res_f = bad_plan_dir / "flash-run" / "flash_result.json"
    bad_res_f.parent.mkdir(parents=True)
    bad_plan_f.write_text("{not valid json", encoding="utf-8")
    bad_res_f.write_text('{"status":"FLASH_AND_READBACK_VERIFIED"}', encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        execute_flash(bad_plan_f, tools_dir=synthetic_env["tools_dir"], execute=True)
    assert not bad_res_f.exists()

    # (c) Failed password rotation preserves existing working openwrt-credentials.json intact (only stages .pending.json)
    keep_cred_dir = tmp_path / "keep_cred_fail"
    keep_cred_dir.mkdir()
    keep_cred_f = keep_cred_dir / "openwrt-credentials.json"
    keep_cred_f.write_text(json.dumps({"host": "192.168.77.1", "username": "root", "password": "WorkingOldPassword!"}), encoding="utf-8")
    with (
        patch("provision_openwrt.detect_host_platform", return_value="linux-x64"),
        patch("provision_openwrt.wait_for_openwrt_ssh", return_value=MagicMock()),
        patch("provision_openwrt._probe_remote_identity_and_usb_mode", return_value={"board_id": "6", "usb_mode": "ncm", "host_hash": "abc"}),
        patch("provision_openwrt.open_remote_fs", return_value=MagicMock()),
        patch("provision_openwrt._ensure_rootfs_grown", return_value={"status": "ok"}),
        patch("provision_openwrt._ensure_board6_card_patch", return_value="sha"),
        patch("provision_openwrt._ensure_capacity_ui", return_value={"status": "ok"}),
        patch("provision_openwrt._ensure_5s_buttons", return_value={"status": "ok"}),
        patch("provision_openwrt.ssh_run", return_value=(0, "", "")),
        patch("provision_openwrt._set_root_password_ssh", side_effect=RuntimeError("router rejected passwd")),
    ):
        with pytest.raises(RuntimeError, match="router rejected passwd"):
            provision_openwrt(
                profile_id="2-dual-stock-openwrt",
                root_password="RejectedNewPassword!",
                out_dir=keep_cred_dir,
                isolate_host=False,
                reboot_after=False,
            )
    assert json.loads(keep_cred_f.read_text(encoding="utf-8"))["password"] == "WorkingOldPassword!"

    # (d) Stale --target-iface / leaking route audit blocks Win10 NCM serial recovery in wait_for_openwrt_ssh
    from provision_openwrt import wait_for_openwrt_ssh

    mono_ser = iter([0.0, 0.1, 6.0, 6.5, 50.0])
    with (
        patch("provision_openwrt.detect_host_platform", return_value="win64"),
        patch("provision_openwrt._prepare_host_rndis", return_value={"network_isolation": {"status": "no_target_matched"}}),
        patch("provision_openwrt.audit_default_routes", return_value={"usb_default_route_leak": True, "leaks": [{"ifIndex": 9}]}),
        patch("provision_openwrt._find_win_broken_ncm_serial_port", side_effect=AssertionError("Must not invoke serial recovery while route leaks")),
        patch("provision_openwrt.connect_ssh", side_effect=AssertionError("Must not connect SSH while route leaks")),
        patch("provision_openwrt.time.monotonic", side_effect=lambda: next(mono_ser, 99.0)),
        patch("provision_openwrt.time.sleep"),
        pytest.raises(TimeoutError, match="no_target_matched"),
    ):
        wait_for_openwrt_ssh("192.168.77.1", timeout=20, target_iface="StaleIface")

    # (e) Failed post-reboot ADB identity check must NOT run cleanup rm -f on the rejected unit
    post_reject_su_cmds: list[str] = []
    boot_phase = {"after_reboot": False}

    def _adb_post_swap(_e, args, **k):
        j = " ".join(args)
        if args == ["reboot"]:
            boot_phase["after_reboot"] = True
            return ""
        if "boot_id" in j:
            return "11111111-1111-4111-8111-111111111111"
        if "pm list" in j:
            return "package:com.minikano.f50_sms uid:10234\n"
        return ""

    def _su_post_swap(_e, script, **k):
        if boot_phase["after_reboot"]:
            post_reject_su_cmds.append(script)
            if "board_id" in script:
                return "6\n"
            return "0" * 64 + "\n"  # swapped unit after reboot!
        return _p3_id_reply(script) or ""

    with (
        patch("provision_android.resolve_tool", return_value=tmp_path / "adb"),
        patch("provision_android.apply_slot_a_from_openwrt", return_value={}),
        patch("provision_android.wait_for_adb_slot_a", return_value="_a"),
        patch("provision_android._adb", side_effect=_adb_post_swap),
        patch("provision_android._su", side_effect=_su_post_swap),
        patch("provision_android.time.sleep"),
        pytest.raises(RuntimeError, match="Target device identity mismatch on Android ADB post-reboot"),
    ):
        provision_android(plan_path=out_p3 / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], return_to_openwrt=False)
    assert not any("f50pro-keep-android-test" in c for c in post_reject_su_cmds)

    # (f) Standalone kit.py provision-openwrt requires --plan
    with pytest.raises(SystemExit):
        kit_main(["provision-openwrt", "--profile", "2-dual-stock-openwrt"])

    # 8. Final hardening polish regressions:
    # (a) JSON null --plan file & mismatched plan profile rejected by provision_openwrt
    null_plan_f = tmp_path / "null_plan.json"
    null_plan_f.write_text("null\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Flash plan must be a JSON object"):
        provision_openwrt(profile_id="2-dual-stock-openwrt", plan_path=null_plan_f, isolate_host=False)
    with pytest.raises(ValueError, match="Flash plan profile mismatch"):
        provision_openwrt(profile_id="2-dual-stock-openwrt", plan_path=out_res / "flash_plan.json", isolate_host=False)

    # (b) Post-SSH route audit failure resets route_audit_ok=False so serial recovery does NOT fire in the same iteration
    mono_post_leak = iter([0.0, 6.0, 6.5, 50.0])
    iso_seq = iter([
        {"network_isolation": {"status": "no_target_matched"}},
        {"network_isolation": {"status": "no_target_matched"}},
    ])
    aud_seq = iter([
        {"usb_default_route_leak": False},
        {"usb_default_route_leak": True, "leaks": [{"ifIndex": 9}]},
    ])
    with (
        patch("provision_openwrt.detect_host_platform", return_value="win64"),
        patch("provision_openwrt._prepare_host_rndis", side_effect=lambda **k: next(iso_seq)),
        patch("provision_openwrt.audit_default_routes", side_effect=lambda **k: next(aud_seq)),
        patch("provision_openwrt.connect_ssh", return_value=MagicMock()),
        patch("provision_openwrt.ssh_run", return_value=(0, "f50pro\n", "")),
        patch("provision_openwrt._find_win_broken_ncm_serial_port", side_effect=AssertionError("Must not run serial recovery after post-SSH leak")),
        patch("provision_openwrt.time.monotonic", side_effect=lambda: next(mono_post_leak, 99.0)),
        patch("provision_openwrt.time.sleep"),
        pytest.raises(TimeoutError, match="Refusing un-isolated OpenWrt SSH session"),
    ):
        wait_for_openwrt_ssh("192.168.77.1", timeout=20)

    # (c) When retry authenticated via *.pending.json, promote working pending password to main creds BEFORE overwriting pending
    pend_dir = tmp_path / "pend_promote"
    pend_dir.mkdir()
    main_cf = pend_dir / "openwrt-credentials.json"
    pend_cf = pend_dir / "openwrt-credentials.pending.json"
    main_cf.write_text(json.dumps({"host": "192.168.77.1", "username": "root", "password": "StaleOlderPassword!"}), encoding="utf-8")
    pend_cf.write_text(json.dumps({"host": "192.168.77.1", "username": "root", "password": "LivePendingPassword!"}), encoding="utf-8")
    authed_ssh = MagicMock()
    authed_ssh._f50pro_auth_password = "LivePendingPassword!"
    with (
        patch("provision_openwrt.detect_host_platform", return_value="linux-x64"),
        patch("provision_openwrt.wait_for_openwrt_ssh", return_value=authed_ssh),
        patch("provision_openwrt._probe_remote_identity_and_usb_mode", return_value={"board_id": "6", "usb_mode": "ncm", "host_hash": "abc"}),
        patch("provision_openwrt.open_remote_fs", return_value=MagicMock()),
        patch("provision_openwrt._ensure_rootfs_grown", return_value={"status": "ok"}),
        patch("provision_openwrt._ensure_board6_card_patch", return_value="sha"),
        patch("provision_openwrt._ensure_capacity_ui", return_value={"status": "ok"}),
        patch("provision_openwrt._ensure_5s_buttons", return_value={"status": "ok"}),
        patch("provision_openwrt.ssh_run", return_value=(0, "", "")),
        patch("provision_openwrt._set_root_password_ssh", side_effect=RuntimeError("second rotation failed")),
    ):
        with pytest.raises(RuntimeError, match="second rotation failed"):
            provision_openwrt(
                profile_id="2-dual-stock-openwrt",
                root_password="ThirdFailedPassword!",
                out_dir=pend_dir,
                isolate_host=False,
                reboot_after=False,
            )
    assert json.loads(main_cf.read_text(encoding="utf-8"))["password"] == "LivePendingPassword!"

    # (d) AGENT-FLASH.md Step 6 provision-openwrt example includes --plan
    agent_doc = (REPO_ROOT / "AGENT-FLASH.md").read_text(encoding="utf-8")
    assert "kit.py provision-openwrt" in agent_doc and "--plan build\\device-session\\build\\flash_plan.json" in agent_doc


def test_wifi_repeater_assets_hardening_and_provision_upload() -> None:
    """Wi-Fi repeater assets satisfy driver/ujail/awk/ucode invariants and upload cleanly in provision_openwrt."""
    from provision_openwrt import WIFI_REPEATER_FILES, _ensure_wifi_repeater

    rep_dir = ASSETS_DIR / "openwrt-patch" / "wifi-repeater"
    assert len(WIFI_REPEATER_FILES) == 7
    for local_name, _remote_path, _mode in WIFI_REPEATER_FILES:
        p = rep_dir / local_name
        assert p.is_file(), f"Missing repeater asset {p}"
        raw = p.read_bytes()
        assert b"\r\n" not in raw, f"CRLF found in {local_name}"

    # Validate JSON assets (menu + ACL)
    menu = json.loads((rep_dir / "luci-app-f50pro-repeater.menu.json").read_text(encoding="utf-8"))
    acl = json.loads((rep_dir / "luci-app-f50pro-repeater.acl.json").read_text(encoding="utf-8"))
    assert "admin/network/wifi-repeater" in menu
    assert "luci-app-f50pro-repeater" in acl
    assert "f50pro-repeater" in acl["luci-app-f50pro-repeater"]["read"]["ubus"]
    assert "connect" in acl["luci-app-f50pro-repeater"]["write"]["ubus"]["f50pro-repeater"]

    # Validate shell daemon/hotplug hardening invariants discovered on live B28 hardware
    sh_txt = (rep_dir / "f50pro-wifi-repeater.sh").read_text(encoding="utf-8")
    assert "chown root:network" in sh_txt and "chmod 640" in sh_txt
    assert "chmod 600" not in sh_txt  # hostapd runs as ujail -U network -G network
    assert "if (!found && iface" in sh_txt  # BusyBox awk runs END even after exit
    assert "/sys/class/ieee80211/phy0/macaddress" in sh_txt  # dynamic per-device MAC
    assert "[ ! -d /sys/class/ieee80211/phy0 ]" in sh_txt  # cold-boot SDIO probe guard
    # Functions called from cmd_watchdog must return, never exit the daemon
    for fn_name in ("cmd_ensure_ap()", "cmd_fallback_ap()"):
        start = sh_txt.index(fn_name)
        end = sh_txt.index("\n}\n", start)
        assert "exit 0" not in sh_txt[start:end], f"{fn_name} must use return, not exit"

    # Validate rpcd ucode backend invariants (no regex NUL bug, no key leak, band saved/restored, newline-safe)
    rpcd_txt = (rep_dir / "f50pro-repeater.rpcd").read_text(encoding="utf-8")
    assert "function has_ctrl(" in rpcd_txt
    assert "\\x00" not in rpcd_txt  # POSIX regcomp truncates on embedded NUL
    assert "f50pro_band" in rpcd_txt
    assert "it.ssid + '|||' + it.band" in rpcd_txt
    assert "'\\0'" not in rpcd_txt
    assert "5c:ff:a9:50:64" not in rpcd_txt  # zero device-specific MACs
    assert "5c:ff:a9:50:64" not in sh_txt

    # Validate LuCI view JS syntax if node is available on CI/host
    js_path = rep_dir / "wifi-repeater.js"
    js_txt = js_path.read_text(encoding="utf-8")
    assert "apEncSelect.addEventListener('change'" in js_txt
    assert "object: 'f50pro-repeater'" in js_txt
    node_exe = shutil.which("node")
    if node_exe:
        chk = subprocess.run([node_exe, "--check", str(js_path)], capture_output=True, text=True)
        assert chk.returncode == 0, f"JS syntax error: {chk.stderr}"

    # Verify _ensure_wifi_repeater uploads all 7 files with exact permissions and runs sh -n + enable/restart
    uploaded: list[tuple[str, int]] = []
    cmds: list[str] = []
    with (
        patch(
            "provision_openwrt.sftp_put_bytes",
            side_effect=lambda _sftp, _data, rpath, mode=0o644: uploaded.append((rpath, mode)),
        ),
        patch("provision_openwrt.ssh_run", side_effect=lambda _ssh, cmd, **kw: cmds.append(cmd) or (0, "", "")),
    ):
        res = _ensure_wifi_repeater(MagicMock(), MagicMock())
    assert res["installed"] is True
    assert res["luci_path"] == "admin/network/wifi-repeater"
    assert uploaded == [(rpath, mode) for _, rpath, mode in WIFI_REPEATER_FILES]
    assert len(cmds) == 1
    assert "sh -n /usr/libexec/f50pro-wifi-repeater.sh" in cmds[0]
    assert "/etc/init.d/f50pro-repeater enable" in cmds[0]
    assert "/tmp/luci-indexcache*" in cmds[0]

    # Verify ucode fallback hostapd bugfix (no JS .push() method in ucode) & safe_ifname quoting
    assert "lines.push(" not in sh_txt
    assert "push(lines," in sh_txt
    assert 'HOSTAPD_OUT}.tmp' in sh_txt
    assert "ieee80211ax=1" in sh_txt
    assert "function safe_ifname(" in rpcd_txt
    assert "'iw dev ' + dev +" not in rpcd_txt
    assert "\"iw dev '\" + dev + \"' link 2>/dev/null\"" in rpcd_txt
    assert "f50pro-key-dispatch" not in rpcd_txt  # keep pure public kit free of personal modular addons


def test_win64_unisoc_driver_all_flag_and_doc_sync(tmp_path: Path) -> None:
    """Verify --force --all offline WinUSB pre-install fix across repo wrapper, fetch_assets normalizer, and docs."""
    import zipfile

    from common import sha256_file, write_json

    # 1. Repo-tracked wrapper checks admin privileges and passes --force --all
    repo_bat = (REPO_ROOT / "scripts" / "install_unisoc_drivers.bat").read_text(encoding="utf-8")
    assert "net session" in repo_bat
    assert "--force --all" in repo_bat
    assert "unisoc_drivers.txt" in repo_bat

    # 2. fetch_and_extract auto-normalizes extracted (and pre-cached) host_tools_win64 install_unisoc_drivers.bat
    cache_d = tmp_path / "cache"
    tools_d = tmp_path / "tools"
    cache_d.mkdir()
    zip_path = cache_d / "f50pro-host-tools-win64.zip"
    old_bat = b'@echo off\r\n"%~dp0qmk_driver_installer.exe" --force "%~dp0unisoc_drivers.txt"\r\n'
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("qmk_driver_installer/qmk_driver_installer.exe", b"MZ-stub")
        zf.writestr("qmk_driver_installer/unisoc_drivers.txt", b"winusb,Unisoc BROM,1782,4D00,guid\n")
        zf.writestr("qmk_driver_installer/install_unisoc_drivers.bat", old_bat)

    manifest_file = tmp_path / "manifest.json"
    zip_sha = sha256_file(zip_path)
    write_json(
        manifest_file,
        {
            "release_tag": "v-test",
            "github_repo": "tanjiu90/f50pro-dualboot-kit",
            "base_url": "https://example.invalid/v-test",
            "packs": {
                "host_tools_win64": {
                    "filename": "f50pro-host-tools-win64.zip",
                    "bytes": zip_path.stat().st_size,
                    "sha256": zip_sha,
                    "platforms": ["win64"],
                }
            },
        },
    )
    with patch("fetch_assets.MANIFEST_PATH", manifest_file):
        r1 = fetch_and_extract(
            explicit_packs=["host_tools_win64"],
            cache_dir=cache_d,
            tools_dir=tools_d,
            local_release_dir=cache_d,
            offline_only=True,
        )
        assert r1["packs"]["host_tools_win64"]["status"] == "extracted"
        bat_path = tools_d / "host-tools-win64" / "qmk_driver_installer" / "install_unisoc_drivers.bat"
        assert b"--force --all" in bat_path.read_bytes()

        # Subsequent run stays cached and valid
        r2 = fetch_and_extract(
            explicit_packs=["host_tools_win64"],
            cache_dir=cache_d,
            tools_dir=tools_d,
            local_release_dir=cache_d,
            offline_only=True,
        )
        assert r2["packs"]["host_tools_win64"]["status"] == "cached"

        # Simulate pre-existing v1.1.1 extracted cache without --all -> re-run upgrades it cleanly
        from fetch_assets import _build_extracted_manifest

        bat_path.write_bytes(old_bat)
        sub_out = tools_d / "host-tools-win64"
        (sub_out / ".verified.manifest.json").write_text(
            json.dumps(_build_extracted_manifest(sub_out, zip_sha)), encoding="utf-8"
        )
        r3 = fetch_and_extract(
            explicit_packs=["host_tools_win64"],
            cache_dir=cache_d,
            tools_dir=tools_d,
            local_release_dir=cache_d,
            offline_only=True,
        )
        assert r3["packs"]["host_tools_win64"]["status"] == "cached"
        assert b"--force --all" in bat_path.read_bytes()

    # 3. Docs and bootstrap.ps1 stay aligned on v1.1.2 + --force --all
    for rel in ("scripts/bootstrap.ps1", "docs/beginner-guide.md", "docs/recovery-and-safety.md", "AGENT-FLASH.md"):
        txt = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert "--force --all" in txt, f"{rel} missing --force --all"
    for rel in ("README.md", "AGENT-FLASH.md", "docs/beginner-guide.md"):
        txt = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert "--branch v1.1.3" in txt, f"{rel} not updated to --branch v1.1.3"
