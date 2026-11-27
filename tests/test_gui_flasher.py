"""Behavioral & adversarial fault-injection tests for Windows GUI, trust-anchored updater, rollback-a, host restore, and worker safety."""
from __future__ import annotations

import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from brom_backup import parse_partition_xml, verify_backup_dir
from build_images import build_profile
from common import sha256_bytes, write_json
from fetch_assets import _build_download_urls, _locate_or_fetch_archive, fetch_and_extract
from flash_images import execute_rollback_a
from gui.diagnostics import (
    build_sanitized_diagnostic_report,
    check_native_tool_path_compat,
    diagnose_failure,
    evaluate_driver_install_result,
    extract_last_json_object,
    parse_pnp_usb_devices,
    parse_pnputil_unisoc_drivers,
    repair_usb_network_via_worker,
    sanitize_diagnostic_text,
    verify_win64_driver_installer_integrity,
)
from gui.github_updater import (
    _safe_extract_tar_gz,
    download_and_verify_kit_release,
    normalize_mirror_prefix,
    parse_sha256sums,
    verify_cached_kit_tree,
)
from host_network import restore_network_snapshot
from kit import _merge_stdin_secrets, build_parser


def _make_sym_info(name: str, target: str) -> tarfile.TarInfo:
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.SYMTYPE
    ti.linkname = target
    return ti


def _make_file_info(name: str, data: bytes) -> tarfile.TarInfo:
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    return ti


def _make_dir_info(name: str) -> tarfile.TarInfo:
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.DIRTYPE
    return ti


def _build_compat_kit_tar_bytes(
    prefix: str,
    *,
    protocol_version: int = 2,
    rootfs_name: str = "openwrt-f50pro-25.12.5-base-rootfs.ext4",
    openwrt_base_sha: str = "ebd302a22b3542057913d499390990f1ca1aeb87bd85d0b37024a77c2ba522b1",
    extra_kit_text: str = "",
) -> bytes:
    buf = io.BytesIO()
    kit_body = (
        f"KIT_PROTOCOL_VERSION = {protocol_version}\n"
        f"CAPABILITIES = ('--secrets-stdin', '--expected-plan-sha256', 'rollback-a')\n"
        f"{extra_kit_text}\n"
    ).encode("utf-8")
    build_body = f'ROOTFS = "{rootfs_name}"\n'.encode("utf-8")
    manifest_body = json.dumps(
        {"release_tag": "v1.1.0", "packs": {"openwrt_base": {"sha256": openwrt_base_sha}}}
    ).encode("utf-8")
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for rel, body in (
            (f"{prefix}/scripts/kit.py", kit_body),
            (f"{prefix}/scripts/build_images.py", build_body),
            (f"{prefix}/assets/release-manifest.json", manifest_body),
        ):
            tf.addfile(_make_file_info(rel, body), io.BytesIO(body))
    return buf.getvalue()


def test_parse_pnputil_unisoc_drivers_utf16_and_mixed_live_brom_bindings(tmp_path: Path) -> None:
    """Driver store parser reads UTF-16LE BOM + UTF-8 INFs; mixed live BROM bindings (1 WinUSB + 1 sprdvcom) MUST fail."""
    (tmp_path / "oem10.inf").write_bytes(
        ('Provider="libwdi"\nDeviceID="VID_1782&PID_4D00"\nInclude=winusb.inf\n').encode("utf-16")
    )
    (tmp_path / "oem11.inf").write_bytes(
        ('Provider="libwdi"\nDeviceID="VID_1782&PID_4D03"\nInclude=winusb.inf\n').encode("utf-16")
    )
    (tmp_path / "oem99.inf").write_text(
        'Desc="SPRD U2S Diag"\nDeviceID="VID_1782&PID_4D00"\nService=sprdvcom\n', encoding="utf-8"
    )
    pnputil_out = "Published Name: oem10.inf\nPublished Name: oem11.inf\nPublished Name: oem99.inf\n"
    res = parse_pnputil_unisoc_drivers(pnputil_out, inf_dir=tmp_path)
    assert res["installed"] is True
    assert res["has_4d00_winusb"] is True and res["has_4d03_winusb"] is True
    assert set(res["winusb_infs"]) == {"oem10.inf", "oem11.inf"}
    assert res["conflicting_serial_infs"] == ["oem99.inf"]

    # Partial store (missing 4D03) fails strict verdict even when installer prints Success
    partial_store = parse_pnputil_unisoc_drivers("Published Name: oem10.inf\n", inf_dir=tmp_path)
    assert partial_store["installed"] is False
    assert evaluate_driver_install_result(returncode=0, output="Success", driver_store=partial_store)["ok"] is False

    # Mixed live bindings: one WinUSB + one sprdvcom MUST STILL flag BROM_DRIVER_NOT_WINUSB!
    mixed_live = parse_pnp_usb_devices(
        [
            {"PNPDeviceID": r"USB\VID_1782&PID_4D00\1", "Name": "Unisoc BROM", "Service": "WinUSB", "ConfigManagerErrorCode": 0},
            {"PNPDeviceID": r"USB\VID_1782&PID_4D03\2", "Name": "SPRD U2S Diag", "Service": "sprdvcom", "ConfigManagerErrorCode": 0},
        ]
    )
    assert any(i["code"] == "BROM_DRIVER_NOT_WINUSB" for i in mixed_live["issues"])
    assert evaluate_driver_install_result(returncode=0, output="Success", driver_store=res, live_usb=mixed_live)["ok"] is False

    # Valid Windows directory with '&' is no longer over-rejected
    assert check_native_tool_path_compat(Path(r"D:\Tools&Utils\F50Pro"))["ok"] is True
    assert check_native_tool_path_compat(Path("D:\\Bad<Dir"))["ok"] is False


def test_parse_pnp_usb_devices_nested_json_openwrt_repair_and_stock_validation() -> None:
    """OpenWrt repair accurately parses production-shaped nested JSON and checks bind/isolation/leak/mgmt postconditions."""
    # Production-shaped nested JSON output from host_network.py isolate
    nested_isolate = json.dumps(
        {
            "isolated": [{"name": "以太网 6", "ifIndex": 30, "ip": "192.168.77.12"}],
            "readback": [
                {
                    "name": "以太网 6",
                    "ifIndex": 30,
                    "query_ok": True,
                    "ip_ok": True,
                    "dhcp": "Disabled",
                    "metric": 5000,
                    "ipv6_enabled": False,
                    "dns_count": 0,
                    "register_dns": False,
                }
            ],
            "target_default_routes": [],
            "query_errors": [],
            "audit": {"host_platform": "win64", "usb_default_route_leak": False, "leaks": []},
            "ignored": [],
        },
        indent=2,
        ensure_ascii=False,
    )
    nested_isolate_no_readback = json.dumps(
        {
            "isolated": [{"name": "以太网 6", "ifIndex": 30, "ip": "192.168.77.12"}],
            "target_default_routes": [],
            "query_errors": [],
            "audit": {"host_platform": "win64", "usb_default_route_leak": False, "leaks": []},
            "ignored": [],
        },
        ensure_ascii=False,
    )
    parsed_nested = extract_last_json_object("[INFO] isolating...\n" + nested_isolate + "\n")
    assert parsed_nested is not None
    assert len(parsed_nested["isolated"]) == 1
    assert parsed_nested["audit"]["usb_default_route_leak"] is False

    # Real CIM field schema for OpenWrt Win10 CDC-NCM Code 28 + mixed modes preservation
    st_mix = parse_pnp_usb_devices(
        [
            {"PNPDeviceID": r"USB\VID_1D6B&PID_0104&MI_00\7&1b524c66&0&0000", "Name": "UsbNcm Host Device", "Service": "", "ConfigManagerErrorCode": 28},
            {"PNPDeviceID": r"USB\VID_19D2&PID_0246&MI_00\1", "Name": "Remote NDIS", "Service": "usbrndis6", "ConfigManagerErrorCode": 0},
        ],
        openwrt_ssh_open=False,
    )
    assert st_mix["state"] == "openwrt"
    assert set(st_mix["present_modes"]) == {"openwrt", "stock_android"}
    assert any(i["code"] == "OPENWRT_WIN10_NCM_ERROR" for i in st_mix["issues"])

    # OpenWrt repair with production-shaped nested JSON + reachable management port succeeds
    def worker_prod(sub: list[str]) -> tuple[int, str]:
        if sub[0] == "bind-rndis":
            return 0, json.dumps({"status": "bound"})
        if sub[0] == "isolate":
            return 0, "[INFO] done\n" + nested_isolate
        if sub[0] == "audit":
            return 0, json.dumps({"host_platform": "win64", "usb_default_route_leak": False, "query_errors": []})
        return 0, "{}"

    r_ok = repair_usb_network_via_worker(
        run_host_net_fn=worker_prod,
        usb_state={"state": "openwrt", "issues": []},
        probe_openwrt_mgmt_fn=lambda: True,
    )
    assert r_ok["ok"] is True and r_ok["isolated_count"] == 1 and r_ok["mgmt_reachable"] is True

    # OpenWrt repair MUST fail if management port is unreachable OR bind-rndis fails
    r_unreach = repair_usb_network_via_worker(
        run_host_net_fn=worker_prod,
        usb_state={"state": "openwrt", "issues": []},
        probe_openwrt_mgmt_fn=lambda: False,
    )
    assert r_unreach["ok"] is False

    def worker_bind_fail(sub: list[str]) -> tuple[int, str]:
        if sub[0] == "bind-rndis":
            return 1, json.dumps({"error": "access_denied"})
        return worker_prod(sub)

    r_bind_fail = repair_usb_network_via_worker(
        run_host_net_fn=worker_bind_fail,
        usb_state={"state": "openwrt", "issues": []},
        probe_openwrt_mgmt_fn=lambda: True,
    )
    assert r_bind_fail["ok"] is False

    # OpenWrt repair MUST fail when isolation readback verification is missing/empty
    def worker_no_readback(sub: list[str]) -> tuple[int, str]:
        if sub[0] == "isolate":
            return 0, nested_isolate_no_readback
        return worker_prod(sub)

    r_no_rb = repair_usb_network_via_worker(
        run_host_net_fn=worker_no_readback,
        usb_state={"state": "openwrt", "issues": []},
        probe_openwrt_mgmt_fn=lambda: True,
    )
    assert r_no_rb["ok"] is False

    # Stock repair rejects non-MU3356 model AND rejects zero correlated adapters!
    r_stock_wrong = repair_usb_network_via_worker(
        run_host_net_fn=lambda _a: (0, json.dumps({"query_errors": [], "rndis_adapters": []})),
        usb_state={"state": "stock_android", "webui_info": {"model_name": "MU300"}, "issues": []},
    )
    assert r_stock_wrong["ok"] is False
    r_stock_no_nic = repair_usb_network_via_worker(
        run_host_net_fn=lambda _a: (0, json.dumps({"query_errors": [], "rndis_adapters": []})),
        usb_state={"state": "stock_android", "webui_info": {"model_name": "MU3356"}, "issues": []},
    )
    assert r_stock_no_nic["ok"] is False
    r_stock_ok = repair_usb_network_via_worker(
        run_host_net_fn=lambda _a: (0, json.dumps({"query_errors": [], "rndis_adapters": [{"PnpDeviceID": r"USB\VID_19D2&PID_0246&MI_00\1", "Status": "Up"}]})),
        usb_state={"state": "stock_android", "webui_info": {"model_name": "MU3356"}, "issues": []},
    )
    assert r_stock_ok["ok"] is True


def test_diagnose_failure_and_strict_typed_pii_sanitization(tmp_path: Path) -> None:
    """Export scrubs JSON-escaped USB serials, non-86 IMEIs, private drive paths, SSIDs, creds, and unvalidated WebUI values."""
    assert diagnose_failure("readback SHA-256 mismatch; wrote flash_failure_report.json")["code"] == "FLASH_SAFE_STOP"
    assert diagnose_failure("Unisoc BROM\nNo matching device found")["code"] == "DRIVER_MISSING_ALL_FLAG"

    fake_imei_non86 = "35" + "9876543210987"
    fake_iccid = "8986" + "0123456789012345"
    fake_escaped_usb = r'{"PnpDeviceID": "USB\\VID_1D6B&PID_0104&MI_00\\7&1b524c66&0&0000"}'
    fake_private_dir = r"D:\MyPrivateClientDir\F50Work"
    raw_log = "\n".join(
        [
            f'[12:00:01] [INFO] --webui-password MySecretWeb123 --wifi-ssid SecretHomeWiFi password=InlinePass99 path={fake_private_dir}',
            f'[12:00:02] [WARN] imei={fake_imei_non86} iccid={fake_iccid} {fake_escaped_usb} Authorization: Bearer tok_secret_xyz',
            'unstructured raw blob with SECRET_LEAK_LINE_NOT_ALLOWLISTED',
        ]
    )
    cleaned = sanitize_diagnostic_text(raw_log, secrets=["MySecretWeb123"], extra_redact_paths=[fake_private_dir])
    for leaked in (
        "MySecretWeb123",
        "SecretHomeWiFi",
        "InlinePass99",
        "MyPrivateClientDir",
        fake_imei_non86,
        fake_iccid,
        "7&1b524c66&0&0000",
        "tok_secret_xyz",
    ):
        assert leaked not in cleaned

    with (
        patch("gui.diagnostics.inspect_unisoc_drivers", return_value={"installed": True, "has_4d00_winusb": True, "has_4d03_winusb": True, "winusb_infs": ["oem1.inf"], "conflicting_serial_infs": []}),
        patch(
            "gui.diagnostics.detect_usb_device_state",
            return_value={
                "query_ok": True,
                "state": "stock_android",
                "present_modes": ["stock_android"],
                "device_count": 1,
                "error_codes": [],
                "issues": [],
                "webui_info": {"model_name": "MU3356<script>leak</script>", "cr_version": "bad\nmultiline"},
            },
        ),
    ):
        rep = build_sanitized_diagnostic_report(
            kit_version="v1.1.4",
            workspace_dir=tmp_path,
            log_tail=raw_log,
            secrets=["MySecretWeb123"],
            last_diag={"code": "FLASH_SAFE_STOP", "title": "test"},
        )
    assert "SECRET_LEAK_LINE_NOT_ALLOWLISTED" not in rep  # free-form raw stdout dropped!
    assert "<script>" not in rep and "multiline" not in rep  # unvalidated WebUI values rejected!
    assert "oem1.inf" not in rep
    assert "7&1b524c66&0&0000" not in rep
    assert fake_imei_non86 not in rep
    assert "SecretHomeWiFi" not in rep


def test_github_updater_anchors_cache_to_direct_digest_blocks_downgrade_and_bad_tar(tmp_path: Path) -> None:
    """Updater resolves direct GitHub digest BEFORE checking cache, blocks v1.1.3 downgrade & non-25.12.5 kits, and hardens tar."""
    assert normalize_mirror_prefix("https://ghfast.top") == "https://ghfast.top/"
    with pytest.raises(ValueError, match="https://"):
        normalize_mirror_prefix("http://insecure.example")

    tar_v2 = _build_compat_kit_tar_bytes("f50pro-dualboot-kit-v1.1.5", protocol_version=2)
    tar_v2_sha = hashlib.sha256(tar_v2).hexdigest()
    sums_text = f"{tar_v2_sha}  f50pro-dualboot-kit-v1.1.5-src.tar.gz\n"
    assert parse_sha256sums(sums_text)["f50pro-dualboot-kit-v1.1.5-src.tar.gz"] == tar_v2_sha

    # 1. Downgrade to v1.1.3 when bundled is v1.1.4 MUST be rejected immediately
    with pytest.raises(RuntimeError, match="拒绝降级"):
        download_and_verify_kit_release(
            {"source": "github_api_direct", "tag": "v1.1.3", "assets": {}},
            kit_store_dir=tmp_path,
            min_tag="v1.1.4",
        )

    # 2. Same-tag poisoned cache with a DIFFERENT src_sha256 MUST NOT be accepted even if self-consistent!
    store = tmp_path / "trusted-kits"
    poisoned_tar = _build_compat_kit_tar_bytes("f50pro-dualboot-kit-v1.1.5", protocol_version=2, extra_kit_text="# OLD_OR_POISONED")
    poisoned_sha = hashlib.sha256(poisoned_tar).hexdigest()
    assert poisoned_sha != tar_v2_sha
    rel_poison = {
        "source": "github_api_direct",
        "tag": "v1.1.5",
        "assets": {
            "f50pro-dualboot-kit-v1.1.5-src.tar.gz": {
                "url": "https://github.com/tanjiu90/f50pro-dualboot-kit/releases/download/v1.1.5/f50pro-dualboot-kit-v1.1.5-src.tar.gz",
                "sha256": poisoned_sha,
            }
        },
    }
    with patch("gui.github_updater._http_get_bytes", return_value=poisoned_tar):
        r_old = download_and_verify_kit_release(rel_poison, kit_store_dir=store, min_tag="v1.1.4")
        assert r_old["src_sha256"] == poisoned_sha

    # Now official GitHub reports tar_v2_sha for v1.1.5 -> updater MUST reject poisoned cache and download tar_v2!
    rel_real = {
        "source": "github_api_direct",
        "tag": "v1.1.5",
        "assets": {
            "SHA256SUMS.txt": {"url": "https://github.com/tanjiu90/f50pro-dualboot-kit/releases/download/v1.1.5/SHA256SUMS.txt"},
            "f50pro-dualboot-kit-v1.1.5-src.tar.gz": {
                "url": "https://github.com/tanjiu90/f50pro-dualboot-kit/releases/download/v1.1.5/f50pro-dualboot-kit-v1.1.5-src.tar.gz",
                "sha256": "",
            },
        },
    }

    def fake_get(url: str, **kwargs):
        if url.endswith("SHA256SUMS.txt"):
            assert url.startswith("https://github.com/")
            return sums_text.encode("utf-8")
        if url.startswith("https://ghfast.top/"):
            return b"TAMPERED_MIRROR_TAR"
        return tar_v2

    with patch("gui.github_updater._http_get_bytes", side_effect=fake_get):
        r_new = download_and_verify_kit_release(rel_real, kit_store_dir=store, mirror_prefix="https://ghfast.top", min_tag="v1.1.4")
        assert r_new["status"] == "downloaded"
        assert r_new["src_sha256"] == tar_v2_sha
        assert verify_cached_kit_tree(store / "v1.1.5", expected_src_sha256=tar_v2_sha) is not None
        assert verify_cached_kit_tree(store / "v1.1.5", expected_src_sha256=poisoned_sha) is None

    # 3. Incompatible protocol (missing KIT_PROTOCOL_VERSION >= 2) or non-25.12.5 policy MUST be rejected
    bad_proto_tar = _build_compat_kit_tar_bytes("f50pro-dualboot-kit-v1.1.6", protocol_version=1)
    bad_policy_tar = _build_compat_kit_tar_bytes("f50pro-dualboot-kit-v1.1.7", protocol_version=2, extra_kit_text="# theme-f50v3")
    for tag, blob in (("v1.1.6", bad_proto_tar), ("v1.1.7", bad_policy_tar)):
        rel_bad = {
            "source": "github_api_direct",
            "tag": tag,
            "assets": {
                f"f50pro-dualboot-kit-{tag}-src.tar.gz": {
                    "url": f"https://github.com/tanjiu90/f50pro-dualboot-kit/releases/download/{tag}/f50pro-dualboot-kit-{tag}-src.tar.gz",
                    "sha256": hashlib.sha256(blob).hexdigest(),
                }
            },
        }
        with patch("gui.github_updater._http_get_bytes", return_value=blob):
            with pytest.raises(ValueError):
                download_and_verify_kit_release(rel_bad, kit_store_dir=store, min_tag="v1.1.4")

    # 4. Tar extractor rejects symlinks, duplicates, duplicate dirs, file/dir collisions, reserved names, & bad Win chars
    for bad_name, make_bad in (
        ("symlink", lambda tf: tf.addfile(_make_sym_info("pkg/link", "kit.py"))),
        ("reserved", lambda tf: tf.addfile(_make_file_info("pkg/CON.txt", b"x"), io.BytesIO(b"x"))),
        ("badchar", lambda tf: tf.addfile(_make_file_info("pkg/a:ads.txt", b"x"), io.BytesIO(b"x"))),
        ("dup_file", lambda tf: (tf.addfile(_make_file_info("pkg/a.py", b"1"), io.BytesIO(b"1")), tf.addfile(_make_file_info("pkg/a.py", b"2"), io.BytesIO(b"2")))),
        ("dup_dir", lambda tf: (tf.addfile(_make_dir_info("pkg/sub")), tf.addfile(_make_dir_info("pkg/sub")))),
        ("file_dir", lambda tf: (tf.addfile(_make_file_info("pkg/sub", b"1"), io.BytesIO(b"1")), tf.addfile(_make_file_info("pkg/sub/a.py", b"2"), io.BytesIO(b"2")))),
    ):
        bad_arc = tmp_path / f"bad_{bad_name}.tar.gz"
        with tarfile.open(bad_arc, "w:gz") as tf:
            make_bad(tf)
        with pytest.raises(ValueError):
            _safe_extract_tar_gz(bad_arc, tmp_path / f"out_{bad_name}")


def test_fetch_assets_binds_executables_to_zip_and_falls_back_past_corrupt_local(tmp_path: Path) -> None:
    """Tampering both exe AND .verified.manifest.json triggers re-extraction; corrupt first local copy checks second copy/online."""
    cache_d = tmp_path / "cache"
    bad_local = tmp_path / "bad_local"
    tools_d = tmp_path / "tools"
    cache_d.mkdir()
    bad_local.mkdir()

    good_zip = cache_d / "f50pro-host-tools-win64.zip"
    with zipfile.ZipFile(good_zip, "w") as zf:
        zf.writestr("qmk_driver_installer/qmk_driver_installer.exe", b"LEGIT_MZ_INSTALLER")
        zf.writestr("qmk_driver_installer/unisoc_drivers.txt", b"winusb,Unisoc BROM,1782,4D00,guid\n")
        zf.writestr("qmk_driver_installer/install_unisoc_drivers.bat", b'@echo off\r\n"%~dp0qmk_driver_installer.exe" --force --all "%~dp0unisoc_drivers.txt"\r\n')
    good_sha = hashlib.sha256(good_zip.read_bytes()).hexdigest()

    # Put a CORRUPT zip in bad_local (checked first!) -> must fall back to good_zip in cache_d!
    (bad_local / "f50pro-host-tools-win64.zip").write_bytes(b"CORRUPT_FIRST_LOCAL")
    mpath = tmp_path / "manifest.json"
    write_json(
        mpath,
        {
            "release_tag": "v-test",
            "base_url": "https://github.com/tanjiu90/f50pro-dualboot-kit/releases/download/v1.1.0",
            "packs": {"host_tools_win64": {"filename": "f50pro-host-tools-win64.zip", "bytes": good_zip.stat().st_size, "sha256": good_sha, "platforms": ["win64"]}},
        },
    )
    with patch("fetch_assets.MANIFEST_PATH", mpath):
        r1 = fetch_and_extract(
            explicit_packs=["host_tools_win64"],
            cache_dir=cache_d,
            tools_dir=tools_d,
            local_release_dir=bad_local,
            offline_only=True,
        )
        assert r1["packs"]["host_tools_win64"]["status"] == "extracted"
        exe_p = tools_d / "host-tools-win64" / "qmk_driver_installer" / "qmk_driver_installer.exe"
        assert verify_win64_driver_installer_integrity(tools_d, manifest_path=mpath, cache_dir=cache_d)["ok"] is True

        # Attacker tampers BOTH qmk_driver_installer.exe AND .verified.manifest.json in writable tools_d!
        exe_p.write_bytes(b"TROJAN_EXE_PAYLOAD")
        from fetch_assets import _build_extracted_manifest

        sub_out = tools_d / "host-tools-win64"
        (sub_out / ".verified.manifest.json").write_text(json.dumps(_build_extracted_manifest(sub_out, good_sha)), encoding="utf-8")

        # 1. Direct pre-launch verifier MUST refuse trojanized exe
        assert verify_win64_driver_installer_integrity(tools_d, manifest_path=mpath, cache_dir=cache_d)["ok"] is False

        # 2. fetch_and_extract MUST detect archive binding mismatch and re-extract authentic bytes!
        r2 = fetch_and_extract(
            explicit_packs=["host_tools_win64"],
            cache_dir=cache_d,
            tools_dir=tools_d,
            local_release_dir=bad_local,
            offline_only=True,
        )
        assert r2["packs"]["host_tools_win64"]["status"] == "extracted"
        assert exe_p.read_bytes() == b"LEGIT_MZ_INSTALLER"

    # Mirror SHA mismatch still falls back cleanly to direct GitHub
    good_bytes = b"verified-release-archive-bytes"
    good_b_sha = hashlib.sha256(good_bytes).hexdigest()

    class _FakeResp:
        def __init__(self, payload: bytes) -> None:
            self._bio = io.BytesIO(payload)
        def read(self, n: int = -1) -> bytes:
            return self._bio.read(n)
        def __enter__(self) -> "_FakeResp":
            return self
        def __exit__(self, *args: object) -> None:
            return None

    with (
        patch.dict("os.environ", {"F50PRO_GITHUB_MIRROR": "https://ghfast.top"}),
        patch("fetch_assets.urllib.request.urlopen", side_effect=lambda req, timeout=180: _FakeResp(b"BAD" if req.full_url.startswith("https://ghfast.top/") else good_bytes)),
    ):
        arc, used_url = _locate_or_fetch_archive(
            {"filename": "pack.zip", "sha256": good_b_sha},
            "https://github.com/tanjiu90/f50pro-dualboot-kit/releases/download/v1.1.0",
            tmp_path / "cache2",
            None,
        )
    assert arc.read_bytes() == good_bytes
    assert used_url.startswith("https://github.com/")
    assert _build_download_urls("https://github.com/tanjiu90/x")[0].startswith("https://")


def test_controlled_rollback_a_write_before_guard_digest_binding_and_unconfirmed_reset(
    synthetic_env: dict[str, Path], tmp_path: Path
) -> None:
    """execute_rollback_a binds preview digests, blocks unexpected live BCAB, aborts on readback mismatch, and never fakes success when reset_sent=False."""
    out_dir = tmp_path / "rb_build"
    build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="3-dual-full",
        out_dir=out_dir,
        tools_dir=synthetic_env["tools_dir"],
        adb_pubkey_path=synthetic_env["adb_pubkey"],
    )
    plan_path = out_dir / "flash_plan.json"
    dry = execute_rollback_a(plan_path, tools_dir=synthetic_env["tools_dir"], execute=False)
    assert dry["dry_run"] is True and dry["target_slot"] == "_a" and dry["size_bytes"] == 32
    assert len(str(dry.get("unit_identity_sha256") or "")) == 64

    # Digest mismatch MUST fail before opening BROM
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        execute_rollback_a(plan_path, tools_dir=synthetic_env["tools_dir"], expected_rollback_sha256="0" * 64, execute=False)

    bdir = synthetic_env["backup_dir"]
    xml_tbl = parse_partition_xml(bdir / "partition_list.xml")
    stock_misc = (bdir / "misc").read_bytes()
    trial_misc = stock_misc[:2048] + (out_dir / "stage3" / "misc_trial_b.bin").read_bytes() + stock_misc[2080:]

    class _FakeSess:
        def __init__(self, *, live_misc: bytes, corrupt_readback: bool = False, fail_reset: bool = False) -> None:
            self.work_dir = out_dir / "rollback-run"
            self.corrupt_readback = corrupt_readback
            self.fail_reset = fail_reset
            self.wrote = False
            self.closed_reboot: bool | None = None
            self._reset_written = False
            self.live_misc = live_misc

        def switch_dir(self, d: Path) -> None:
            self.work_dir = d

        def table(self, _fn: str) -> dict[str, int]:
            return dict(xml_tbl)

        def read_part(self, part: str, sz: int, _fn: str) -> bytes:
            if part == "misc":
                if self.wrote and self.corrupt_readback:
                    return b"\xff" * len(self.live_misc)
                return self.live_misc[:sz]
            return (bdir / part).read_bytes()[:sz]

        def safe_unlink(self, _fn: str) -> None:
            return None

        def cmd(self, args: list[object], _ok: str, **kw: object) -> str:
            if args[:3] == ["wof", "misc", 2048]:
                staged = Path(str(args[3])).read_bytes()
                self.live_misc = self.live_misc[:2048] + staged + self.live_misc[2080:]
                self.wrote = True
            return "ok"

        def close(self, reboot: bool = False) -> None:
            self.closed_reboot = reboot
            if reboot and self.fail_reset:
                self._reset_written = False
                raise RuntimeError("USB link dropped before reset ACK")
            self._reset_written = reboot

    # 1. Unexpected live BCAB (altered slot _a metadata still pointing to _a) MUST be rejected before write!
    import struct
    import zlib

    weird_bcab = bytearray(stock_misc[2048:2080])
    weird_bcab[12] = 0x55  # altered slot _a metadata still pointing to _a (unexpected state)
    struct.pack_into("<I", weird_bcab, 28, zlib.crc32(bytes(weird_bcab[:28])) & 0xFFFFFFFF)
    weird_misc = stock_misc[:2048] + bytes(weird_bcab) + stock_misc[2080:]
    weird_sess = _FakeSess(live_misc=weird_misc)
    with pytest.raises(RuntimeError, match="Unexpected live misc\\+2048 BCAB"):
        execute_rollback_a(
            plan_path,
            tools_dir=synthetic_env["tools_dir"],
            expected_plan_sha256=dry["plan_sha256"],
            expected_rollback_sha256=dry["rollback_sha256"],
            execute=True,
            active_session=weird_sess,
        )
    assert weird_sess.wrote is False and weird_sess.closed_reboot is False

    # 1b. Real live _b BCAB whose tries_remaining decremented (e.g. tries=2) MUST be accepted cleanly!
    dec_b = bytearray((out_dir / "stage3" / "misc_trial_b.bin").read_bytes())
    dec_b[14] = (dec_b[14] & 0x8F) | (2 << 4)  # decrement slot _b tries from 3 -> 2
    struct.pack_into("<I", dec_b, 28, zlib.crc32(bytes(dec_b[:28])) & 0xFFFFFFFF)
    dec_b_misc = stock_misc[:2048] + bytes(dec_b) + stock_misc[2080:]
    dec_sess = _FakeSess(live_misc=dec_b_misc)
    res_dec = execute_rollback_a(
        plan_path,
        tools_dir=synthetic_env["tools_dir"],
        expected_plan_sha256=dry["plan_sha256"],
        expected_rollback_sha256=dry["rollback_sha256"],
        execute=True,
        active_session=dec_sess,
    )
    assert res_dec["status"] == "ROLLBACK_A_VERIFIED" and res_dec["reset_sent"] is True

    # 2. Readback mismatch aborts without reset
    bad_sess = _FakeSess(live_misc=trial_misc, corrupt_readback=True)
    with pytest.raises(RuntimeError, match="Rollback readback safety check failed"):
        execute_rollback_a(plan_path, tools_dir=synthetic_env["tools_dir"], execute=True, active_session=bad_sess)
    assert bad_sess.closed_reboot is False

    # 3. Unconfirmed reset MUST NOT return ROLLBACK_A_VERIFIED!
    no_rst_sess = _FakeSess(live_misc=trial_misc, fail_reset=True)
    res_no_rst = execute_rollback_a(plan_path, tools_dir=synthetic_env["tools_dir"], execute=True, active_session=no_rst_sess)
    assert res_no_rst["status"] == "ROLLBACK_WRITTEN_RESET_UNCONFIRMED"
    assert res_no_rst["reset_sent"] is False

    # 4. Clean verified write + reset returns ROLLBACK_A_VERIFIED
    ok_sess = _FakeSess(live_misc=trial_misc)
    res_ok = execute_rollback_a(
        plan_path,
        tools_dir=synthetic_env["tools_dir"],
        expected_plan_sha256=dry["plan_sha256"],
        expected_rollback_sha256=dry["rollback_sha256"],
        execute=True,
        active_session=ok_sess,
    )
    assert res_ok["status"] == "ROLLBACK_A_VERIFIED" and res_ok["reset_sent"] is True


def test_windows_restore_snapshot_fails_closed_when_usb_connected_or_pnp_fails(tmp_path: Path) -> None:
    """host_network.restore_network_snapshot refuses Windows restore whenever F50 Pro USB is attached or PnP query fails."""
    snap = tmp_path / "snap.json"
    write_json(
        snap,
        {
            "applied_static_ip": "192.168.77.12",
            "entries": [{"platform": "win64", "name": "Ethernet 6", "pnp_id": r"USB\VID_1D6B&PID_0104&MI_00\1", "dhcp": True}],
        },
    )
    with patch("host_network._ps", return_value=json.dumps({"query_ok": True, "connected_count": 1})):
        with pytest.raises(RuntimeError, match="still connected"):
            restore_network_snapshot(snap, force=False)
        # Even --force MUST NOT bypass the Windows live USB disconnect gate!
        with pytest.raises(RuntimeError, match="still connected"):
            restore_network_snapshot(snap, force=True)
    with patch("host_network._ps", return_value=json.dumps({"query_ok": False, "connected_count": 0})):
        with pytest.raises(RuntimeError, match="PnP safety check failed"):
            restore_network_snapshot(snap, force=False)


def test_secrets_stdin_and_worker_exception_and_untrusted_root_gates(tmp_path: Path) -> None:
    """--secrets-stdin preserves special passwords; worker catches malformed stdin without hanging and rejects untrusted kit_root."""
    parser = build_parser()
    args = parser.parse_args(["auto", "--profile", "3-dual-full", "--secrets-stdin"])
    secret_json = json.dumps({"webui_password": " -weird!pw ", "wifi_password": "-wifi 1234", "root_password": "  -root  "})
    with patch("sys.stdin", io.StringIO(secret_json)):
        _merge_stdin_secrets(args)
    assert args.webui_password == " -weird!pw "
    assert args.wifi_password == "-wifi 1234"
    assert args.root_password == "  -root  "

    # Malformed stdin JSON MUST exit fast with structured worker_error envelope (never hang runw.exe)
    r_bad = subprocess.run(
        [sys.executable, str(REPO_ROOT / "gui" / "flasher_app.py"), "--run-kit", str(REPO_ROOT), "probe", "--secrets-stdin"],
        input="{malformed-json",
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
    )
    assert r_bad.returncode != 0
    assert "worker_error" in (r_bad.stderr + r_bad.stdout)

    # Arbitrary untrusted kit_root MUST be rejected by _dispatch_embedded_script
    fake_kit = tmp_path / "untrusted-kit"
    (fake_kit / "scripts").mkdir(parents=True)
    (fake_kit / "scripts" / "kit.py").write_text("print('pwned')\n", encoding="utf-8")
    r_untrusted = subprocess.run(
        [sys.executable, str(REPO_ROOT / "gui" / "flasher_app.py"), "--run-kit", str(fake_kit), "fetch-assets", "--list-packs"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
    )
    assert r_untrusted.returncode != 0
    assert "UntrustedKitRoot" in (r_untrusted.stderr + r_untrusted.stdout)
    assert "pwned" not in r_untrusted.stdout


def test_embedded_run_kit_worker_mode() -> None:
    """flasher_app.py --run-kit dispatches kit.py cleanly from the bundled kit root."""
    res = subprocess.run(
        [sys.executable, str(REPO_ROOT / "gui" / "flasher_app.py"), "--run-kit", str(REPO_ROOT), "fetch-assets", "--list-packs"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
    )
    assert res.returncode == 0, res.stderr
    payload = json.loads(res.stdout)
    assert payload["release_tag"] == "v1.1.0"
    assert len(payload["packs"]) >= 5


def test_windows_gui_smoke_renders_all_tabs_and_diag_banner() -> None:
    """On Windows, verify the Tkinter GUI initializes all 4 scrollable tabs and auto-troubleshooter banner cleanly."""
    if sys.platform != "win32":
        pytest.skip("Tkinter GUI smoke test requires Windows desktop session")
    res = subprocess.run(
        [sys.executable, str(REPO_ROOT / "gui" / "flasher_app.py"), "--smoke-gui"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
    )
    assert res.returncode == 0, res.stderr
    assert "GUI_SMOKE_OK" in res.stdout


def test_offline_plan_sha256_binding_and_unit_identity_roundtrip(synthetic_env: dict[str, Path], tmp_path: Path) -> None:
    """Offline plan emits 64-hex unit_identity_sha256 + plan_sha256 + android_a_stage; auto enforces --reuse-backup & digest."""
    import kit as kit_mod

    work_dir = tmp_path / "session"
    backup_dir = work_dir / "backup"
    shutil.copytree(synthetic_env["backup_dir"], backup_dir)

    bak_rep = verify_backup_dir(backup_dir, require_complete_table=True)
    assert bak_rep["backup_coverage"]["flashed_targets_and_boot_slots_covered"] is True
    assert bak_rep["backup_coverage"]["full_emmc_including_userdata_and_boot1_covered"] is False

    plan_args = kit_mod.build_parser().parse_args(
        [
            "plan",
            "--profile",
            "3-dual-full",
            "--work-dir",
            str(work_dir),
            "--tools-dir",
            str(synthetic_env["tools_dir"]),
            "--adb-pubkey",
            str(synthetic_env["adb_pubkey"]),
        ]
    )
    rep = kit_mod.run_offline_plan(plan_args)
    assert rep["status"] == "DRY_RUN_READY"
    plan_sha = rep["build"]["plan_sha256"]
    unit_sha = rep["build"]["unit_identity_sha256"]
    assert len(plan_sha) == 64 and len(unit_sha) == 64
    assert rep["build"]["android_a_stage"]["apply_from_openwrt"] is True

    # expected-plan-sha256 without --reuse-backup MUST fail closed
    no_reuse_args = kit_mod.build_parser().parse_args(
        ["auto", "--profile", "3-dual-full", "--work-dir", str(work_dir), "--expected-plan-sha256", plan_sha, "--execute"]
    )
    with pytest.raises(ValueError, match="requires --reuse-backup"):
        kit_mod.run_auto(no_reuse_args)

    (work_dir / "build" / "android_provision_report.json").write_text("{}", encoding="utf-8")

    # Wrong expected_plan_sha256 fails closed WITHOUT clobbering flash_plan.json
    bad_auto_args = kit_mod.build_parser().parse_args(
        [
            "auto",
            "--profile",
            "3-dual-full",
            "--work-dir",
            str(work_dir),
            "--tools-dir",
            str(synthetic_env["tools_dir"]),
            "--adb-pubkey",
            str(synthetic_env["adb_pubkey"]),
            "--reuse-backup",
            "--offline-only",
            "--expected-plan-sha256",
            "0" * 64,
            "--execute",
        ]
    )
    with (
        patch.object(kit_mod, "fetch_and_extract", return_value={"status": "cached", "network_downloads": []}),
        patch.object(kit_mod, "assert_preflight_ready", return_value=None),
        patch.object(kit_mod, "execute_flash", side_effect=AssertionError("must not flash on mismatch")),
    ):
        with pytest.raises(ValueError, match="SHA-256 mismatch"):
            kit_mod.run_auto(bad_auto_args)

    # Matching expected_plan_sha256 reaches execute_flash with identical digest and passes expected_plan_sha256 through
    good_auto_args = kit_mod.build_parser().parse_args(
        [
            "auto",
            "--profile",
            "3-dual-full",
            "--work-dir",
            str(work_dir),
            "--tools-dir",
            str(synthetic_env["tools_dir"]),
            "--adb-pubkey",
            str(synthetic_env["adb_pubkey"]),
            "--reuse-backup",
            "--offline-only",
            "--expected-plan-sha256",
            plan_sha,
            "--execute",
        ]
    )
    called_kw: dict[str, object] = {}

    def _stop_after_flash(plan_p: Path, **kw: object) -> dict[str, object]:
        called_kw["plan_p"] = plan_p
        called_kw["expected_plan_sha256"] = kw.get("expected_plan_sha256")
        raise RuntimeError("STOP_AFTER_FLASH_CHECK")

    with (
        patch.object(kit_mod, "fetch_and_extract", return_value={"status": "cached", "network_downloads": []}),
        patch.object(kit_mod, "assert_preflight_ready", return_value=None),
        patch.object(kit_mod, "execute_flash", side_effect=_stop_after_flash),
    ):
        with pytest.raises(RuntimeError, match="STOP_AFTER_FLASH_CHECK"):
            kit_mod.run_auto(good_auto_args)
    assert called_kw["expected_plan_sha256"] == plan_sha
    assert hashlib.sha256(Path(called_kw["plan_p"]).read_bytes()).hexdigest() == plan_sha


def test_round4_guards_win64_route_hijack_driver_bat_auth_tarball_audit_and_wifi_cred_persist(tmp_path: Path) -> None:
    """Verify Round 4 security/safety guards: win64 internet-exit block, bat PS5.1 auth, --audit-tarball, and Wi-Fi cred save."""
    import host_network as hn

    # 1. win64 internet-exit mode MUST fail closed unless allow_host_route_hijack=True
    with patch.object(hn, "detect_host_platform", return_value="win64"):
        with pytest.raises(RuntimeError, match="allow_host_route_hijack"):
            hn.isolate_usb_rndis_adapter(mode="internet-exit", allow_host_route_hijack=False)

    # 2. build_windows_gui.py --audit-tarball passes on the ENTIRE tracked repo working tree and rejects personal tokens elsewhere
    good_tar = tmp_path / "repo_clean.tar.gz"
    tracked_raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=str(REPO_ROOT))
    tracked_rels = [b.decode("utf-8") for b in tracked_raw.split(b"\x00") if b]
    with tarfile.open(good_tar, "w:gz") as tf:
        for rel in tracked_rels:
            p = REPO_ROOT / rel
            if not p.is_file():
                continue
            data = p.read_bytes()
            tf.addfile(_make_file_info(f"f50pro-dualboot-kit-v1.1.4/{rel}", data), io.BytesIO(data))
    r_clean = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "build_windows_gui.py"), "--audit-tarball", str(good_tar)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
    )
    assert r_clean.returncode == 0, r_clean.stdout + r_clean.stderr
    assert json.loads(r_clean.stdout)["sanitization_ok"] is True

    bad_tar = tmp_path / "repo_personal.tar.gz"
    with tarfile.open(bad_tar, "w:gz") as tf:
        bad_bytes = b"# accidentally leaked theme-f50v3 customization\n"
        tf.addfile(_make_file_info("f50pro-dualboot-kit-v1.1.4/scripts/custom.py", bad_bytes), io.BytesIO(bad_bytes))
    r_bad = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "build_windows_gui.py"), "--audit-tarball", str(bad_tar)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
    )
    assert r_bad.returncode != 0

    # 3. scripts/install_unisoc_drivers.bat PowerShell 5.1 pre-launch auth passes on intact zip and rejects tampered exe
    if sys.platform == "win32":
        bat_lines = (REPO_ROOT / "scripts" / "install_unisoc_drivers.bat").read_text(encoding="utf-8").splitlines()
        auth_lines = [ln for ln in bat_lines if "System.IO.Compression.FileSystem" in ln]
        assert len(auth_lines) == 1
        ps_cmd = auth_lines[0].split('-Command "', 1)[1].rsplit('"', 1)[0]

        fake_repo = tmp_path / "Bob's Repo & Kit"
        qmk_dir = fake_repo / "build" / "runtime-tools" / "host-tools-win64" / "qmk_driver_installer"
        qmk_dir.mkdir(parents=True)
        (fake_repo / "assets").mkdir(parents=True)
        (fake_repo / "bundle-cache").mkdir(parents=True)
        exe_bytes = b"LEGIT_QMK_INSTALLER"
        lst_bytes = b"winusb,Unisoc BROM,1782,4D00,guid\n"
        (qmk_dir / "qmk_driver_installer.exe").write_bytes(exe_bytes)
        (qmk_dir / "unisoc_drivers.txt").write_bytes(lst_bytes)
        zip_p = fake_repo / "bundle-cache" / "f50pro-host-tools-win64.zip"
        with zipfile.ZipFile(zip_p, "w") as zf:
            zf.writestr("qmk_driver_installer/qmk_driver_installer.exe", exe_bytes)
            zf.writestr("qmk_driver_installer/unisoc_drivers.txt", lst_bytes)
        write_json(
            fake_repo / "assets" / "release-manifest.json",
            {
                "release_tag": "v1.1.0",
                "packs": {"host_tools_win64": {"filename": "f50pro-host-tools-win64.zip", "sha256": hashlib.sha256(zip_p.read_bytes()).hexdigest()}},
            },
        )
        env = dict(__import__("os").environ)
        env["PSModulePath"] = str(tmp_path / "empty-psmodules")  # simulate pwsh->powershell 5.1 PSModulePath mismatch
        env["REPO_ROOT"] = str(fake_repo)
        env["INSTALLER"] = str(qmk_dir / "qmk_driver_installer.exe")
        env["LIST"] = str(qmk_dir / "unisoc_drivers.txt")
        r_ps_ok = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], env=env, capture_output=True, text=True, timeout=20)
        assert r_ps_ok.returncode == 0, r_ps_ok.stdout + r_ps_ok.stderr
        # Tamper exe -> MUST fail closed
        (qmk_dir / "qmk_driver_installer.exe").write_bytes(b"TAMPERED_EXE")
        r_ps_bad = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], env=env, capture_output=True, text=True, timeout=20)
        assert r_ps_bad.returncode != 0

    # 4. provision_openwrt persists auto-generated unique Wi-Fi key even when root password is not rotated
    import struct
    import zlib
    import provision_openwrt as po

    valid_b_bcab = bytearray(32)
    valid_b_bcab[0:4] = b"_b\x00\x00"
    valid_b_bcab[4:8] = struct.pack("<I", 0x42414342)
    valid_b_bcab[8] = 1
    valid_b_bcab[9] = 2
    valid_b_bcab[14] = (3 << 4) | 0x0F
    struct.pack_into("<I", valid_b_bcab, 28, zlib.crc32(bytes(valid_b_bcab[:28])) & 0xFFFFFFFF)

    class _DummySSH:
        def close(self) -> None:
            return None

    cred_out = tmp_path / "prov_out"
    with (
        patch.object(po, "wait_for_openwrt_ssh", return_value=_DummySSH()),
        patch.object(po, "_probe_remote_identity_and_usb_mode", return_value={"board_id": "u30pro", "usb_mode": "rndis"}),
        patch.object(
            po,
            "resolve_host_usb_net_plan",
            return_value={"switch_required": False, "install_usb_net_mode": "rndis", "final_usb_net_mode": "rndis"},
        ),
        patch.object(po, "open_remote_fs", return_value=object()),
        patch.object(po, "_ensure_rootfs_grown", return_value={"status": "ok"}),
        patch.object(po, "_ensure_board6_card_patch", return_value="a" * 64),
        patch.object(po, "_ensure_capacity_ui", return_value={"status": "ok"}),
        patch.object(po, "_ensure_5s_buttons", return_value={"status": "ok"}),
        patch.object(po, "_ensure_wifi_repeater", return_value={"status": "ok"}),
        patch.object(po, "ssh_run", return_value="ok"),
        patch.object(po, "sftp_get_bytes", return_value=bytes(valid_b_bcab)),
    ):
        prov_res = po.provision_openwrt(
            profile_id="3-dual-full",
            out_dir=cred_out,
            root_password=None,
            generate_password=False,
            wifi_password=None,
            isolate_host=False,
            reboot_after=False,
        )
    cred_file = cred_out / "openwrt-credentials.json"
    assert cred_file.is_file()
    saved = json.loads(cred_file.read_text(encoding="utf-8"))
    assert len(saved.get("wifi_password", "")) >= 16
    assert saved.get("wifi_ssid") == "F50Pro-OpenWrt"
    assert prov_res["credentials_file"] == str(cred_file)
