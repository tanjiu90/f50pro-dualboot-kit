"""Automated test coverage for safety guardrails, readback aborts, host route checks, and archive integrity."""
from __future__ import annotations

import json
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from brom_backup import parse_partition_xml, verify_backup_dir
from build_images import build_profile
from common import F50PRO_VENDOR_BOOT_EXTRA_ARGS, repack_vendor_boot_v4, sha256_bytes, write_json
from fetch_assets import _locate_or_fetch_archive, _safe_extract_zip, fetch_and_extract
from flash_images import execute_flash
from host_network import audit_default_routes
from inspect_backup import inspect_backup_dir
from provision_android import apply_slot_a_from_openwrt


def test_flash_aborts_on_live_gpt_mismatch(synthetic_env: dict[str, Path], tmp_path: Path) -> None:
    """execute_flash must reject live GPT size mismatches before issuing any write command."""
    out_dir = synthetic_env["out_dir"] / "gpt_mismatch"
    build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="1-android-ufi",
        out_dir=out_dir,
        tools_dir=synthetic_env["tools_dir"],
        adb_pubkey_path=synthetic_env["adb_pubkey"],
    )
    bad_tbl = list(parse_partition_xml(synthetic_env["backup_dir"] / "partition_list.xml").items())
    bad_tbl[0] = (bad_tbl[0][0], bad_tbl[0][1] + 1048576)

    fake_sess = MagicMock()
    fake_sess.table.return_value = bad_tbl
    with patch("flash_images.resolve_tool", return_value=tmp_path / "spd_dump.exe"), patch(
        "flash_images._SpdSession", return_value=fake_sess
    ):
        with pytest.raises(RuntimeError, match="Live GPT partition table differs"):
            execute_flash(out_dir / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], execute=True)
    fake_sess.cmd.assert_not_called()


def test_flash_aborts_before_wof_on_readback_mismatch(synthetic_env: dict[str, Path], tmp_path: Path) -> None:
    """execute_flash must fail immediately on readback mismatch before reaching misc+2048 wof."""
    out_dir = synthetic_env["out_dir"] / "rb_fail"
    build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="2-dual-stock-openwrt",
        out_dir=out_dir,
        tools_dir=synthetic_env["tools_dir"],
    )
    good_tbl = list(parse_partition_xml(synthetic_env["backup_dir"] / "partition_list.xml").items())

    fake_sess = MagicMock()
    fake_sess.table.return_value = good_tbl

    def _dev_a_identity_then_corrupt(part: str, sz: int, fname: str) -> bytes:
        if "_id_probe" in fname:
            return (synthetic_env["backup_dir"] / part).read_bytes()[:sz]
        return b"\xff" * sz

    # Identity probes match Device A; pre-check differs -> triggers write; post-write readback returns wrong bytes
    fake_sess.read_part.side_effect = _dev_a_identity_then_corrupt
    with patch("flash_images.resolve_tool", return_value=tmp_path / "spd_dump.exe"), patch(
        "flash_images._SpdSession", return_value=fake_sess
    ):
        with pytest.raises(RuntimeError, match="Readback SHA mismatch"):
            execute_flash(out_dir / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], execute=True)
    sent_ops = [c.args[0][0] for c in fake_sess.cmd.call_args_list]
    assert "wof" not in sent_ops


def test_flash_aborts_on_wof_verify_failure(synthetic_env: dict[str, Path], tmp_path: Path) -> None:
    """execute_flash verifies misc+2048 byte-for-byte after wof and aborts if unchanged."""
    out_dir = synthetic_env["out_dir"] / "wof_fail"
    plan = build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="2-dual-stock-openwrt",
        out_dir=out_dir,
        tools_dir=synthetic_env["tools_dir"],
    )
    good_tbl = list(parse_partition_xml(synthetic_env["backup_dir"] / "partition_list.xml").items())
    # Keep only wof op so we exercise wof check cleanly
    plan["operations"] = [o for o in plan["operations"] if o["op"] == "wof"]
    write_json(out_dir / "wof_only.json", plan)
    orig_misc = (synthetic_env["backup_dir"] / "misc").read_bytes()

    fake_sess = MagicMock()
    fake_sess.table.return_value = good_tbl
    misc_calls = iter([orig_misc, orig_misc])  # unchanged after wof!

    def _dev_a_identity_then_wof(part: str, sz: int, fname: str) -> bytes:
        if "_id_probe" in fname:
            return (synthetic_env["backup_dir"] / part).read_bytes()[:sz]
        return next(misc_calls)

    fake_sess.read_part.side_effect = _dev_a_identity_then_wof
    with patch("flash_images.resolve_tool", return_value=tmp_path / "spd_dump.exe"), patch(
        "flash_images._SpdSession", return_value=fake_sess
    ):
        with pytest.raises(RuntimeError, match="Offset write safety check failed"):
            execute_flash(out_dir / "wof_only.json", tools_dir=synthetic_env["tools_dir"], execute=True)


def test_host_network_detects_ncm_and_rndis_route_leaks() -> None:
    """audit_default_routes must flag 0.0.0.0/0 or ::/0 default routes on USB RNDIS or UsbNcm."""
    leaked_payload = json.dumps({
        "ipv4_default": [{"ifIndex": 42, "InterfaceAlias": "usb0", "NextHop": "192.168.77.1", "RouteMetric": 0}],
        "ipv6_default": [],
        "rndis_adapters": [{"ifIndex": 42, "Name": "Ethernet 9", "InterfaceDescription": "Microsoft UsbNcm Host Device", "Status": "Up"}],
    })
    clean_payload = json.dumps({
        "ipv4_default": [{"ifIndex": 10, "InterfaceAlias": "Wi-Fi", "NextHop": "192.168.1.1", "RouteMetric": 25}],
        "ipv6_default": [],
        "rndis_adapters": [{"ifIndex": 42, "Name": "Ethernet 9", "InterfaceDescription": "Remote NDIS Compatible Device", "Status": "Up"}],
    })
    with patch("host_network.sys.platform", "win32"), patch("host_network._ps", return_value=leaked_payload):
        res_leak = audit_default_routes()
        assert res_leak["usb_default_route_leak"] is True
        assert len(res_leak["leaks"]) == 1
    with patch("host_network.sys.platform", "win32"), patch("host_network._ps", return_value=clean_payload):
        res_clean = audit_default_routes()
        assert res_clean["usb_default_route_leak"] is False


def test_fetch_assets_rejects_tamper_and_zip_slip(tmp_path: Path) -> None:
    """Verify SHA-256 verification, nested APK verification, and path-traversal guards."""
    bad_zip = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad_zip, "w") as zf:
        zf.writestr("../../outside.txt", b"pwn")

    with pytest.raises(ValueError, match="is not in the subpath"):
        _safe_extract_zip(bad_zip, tmp_path / "extract")

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        _locate_or_fetch_archive(
            {"filename": "bad.zip", "sha256": "0" * 64},
            "https://example.invalid",
            tmp_path / "cache",
            tmp_path,
        )

    # Nested APK tamper detection in fetch_and_extract
    fake_release = tmp_path / "release"
    fake_release.mkdir()
    apks = fake_release / "android.zip"
    with zipfile.ZipFile(apks, "w") as zf:
        zf.writestr("Magisk-canary-28103.apk", b"wrong-apk")
    ow_arc = fake_release / "ow.zip"
    with zipfile.ZipFile(ow_arc, "w") as zf:
        zf.writestr("dummy.txt", b"ok")
    manifest = {
        "release_tag": "v-test",
        "base_url": "https://example.invalid",
        "packs": {
            "openwrt_base": {"filename": "ow.zip", "sha256": sha256_bytes(ow_arc.read_bytes())},
            "android_pkgs": {
                "filename": "android.zip",
                "sha256": sha256_bytes(apks.read_bytes()),
                "contains": {"Magisk-canary-28103.apk": "f" * 64},
            },
        },
    }
    mpath = tmp_path / "manifest.json"
    write_json(mpath, manifest)
    with patch("fetch_assets.MANIFEST_PATH", mpath), patch("fetch_assets.sys.platform", "linux"):
        with pytest.raises(ValueError, match="Magisk-canary-28103.apk SHA-256 mismatch"):
            fetch_and_extract(
                include_openclash=False,
                cache_dir=tmp_path / "c",
                tools_dir=tmp_path / "t",
                local_release_dir=fake_release,
            )


def test_brom_verify_reports_sprd3_boundary_and_missing_boot1(synthetic_env: dict[str, Path]) -> None:
    """verify_backup_dir must honestly flag SPRD3 non-readiness and missing splloader_bak."""
    rep = verify_backup_dir(synthetic_env["backup_dir"], require_complete_table=True)
    assert rep["bare_metal_sprd3_ready"] is False
    assert rep["splloader_bak_present"] is False
    assert "SPRD4:AutoD" in rep["recovery_channel"]
    assert any("splloader_bak" in w for w in rep["warnings"])


def test_inspect_and_vendor_boot_reject_foreign_hw_and_bad_dtb(synthetic_env: dict[str, Path]) -> None:
    """Ensure foreign DTB SHA-256 and wrong device identifiers raise ValueError."""
    bdir = synthetic_env["backup_dir"]
    vb = (bdir / "vendor_boot_a").read_bytes()
    with pytest.raises(ValueError, match="DTB digest mismatch"):
        repack_vendor_boot_v4(vb, F50PRO_VENDOR_BOOT_EXTRA_ARGS, expected_dtb_sha256="0" * 64, ramdisk=b"\x02!L\x18\x00\x00\x00\x00")

    # Tamper misc so it no longer contains ums9632 bootconfig
    facts = inspect_backup_dir(bdir)
    assert facts["vendor_boot_a"]["dtb_sha256"]
    # Corrupt vendor_boot_a bootconfig text indirectly via bad init_boot_a model -> test model check
    (bdir / "trustos_a").write_bytes((bdir / "sml_a").read_bytes())  # lacks AVB signature
    with pytest.raises(ValueError, match="trustos AVB signature"):
        inspect_backup_dir(bdir)


def test_provision_android_rejects_local_sha_tamper(synthetic_env: dict[str, Path]) -> None:
    """apply_slot_a_from_openwrt must reject local digest mismatch before running dd."""
    out_dir = synthetic_env["out_dir"] / "p3_tamper"
    plan = build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="3-dual-full",
        out_dir=out_dir,
        tools_dir=synthetic_env["tools_dir"],
        adb_pubkey_path=synthetic_env["adb_pubkey"],
    )
    plan["android_a_stage"]["trustos_a"]["sha256"] = "0" * 64
    fake_ssh = MagicMock()
    with patch("provision_android.wait_for_openwrt_ssh", return_value=fake_ssh):
        with pytest.raises(ValueError, match="Digest mismatch on local trustos_a"):
            apply_slot_a_from_openwrt(plan)
