"""Unit tests for Windows GUI auto-diagnostics, GitHub Release updater, mirror safety, and --run-kit worker."""
from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fetch_assets import _build_download_urls
from gui.diagnostics import (
    diagnose_failure,
    parse_pnp_usb_devices,
    parse_pnputil_unisoc_drivers,
    sanitize_diagnostic_text,
)
from gui.github_updater import (
    build_candidate_urls,
    download_and_verify_kit_release,
    normalize_mirror_prefix,
    parse_sha256sums,
)


def test_parse_pnputil_unisoc_drivers_detects_winusb_and_serial_conflict(tmp_path: Path) -> None:
    """Driver store parser must verify both 1782:4D00 & 4D03 WinUSB INFs and flag SPRD serial conflicts."""
    (tmp_path / "oem10.inf").write_text(
        'Provider="libwdi"\nDeviceID="VID_1782&PID_4D00"\nInclude=winusb.inf\n', encoding="utf-8"
    )
    (tmp_path / "oem11.inf").write_text(
        'Provider="libwdi"\nDeviceID="VID_1782&PID_4D03"\nInclude=winusb.inf\n', encoding="utf-8"
    )
    (tmp_path / "oem99.inf").write_text(
        'Desc="SPRD U2S Diag"\nDeviceID="VID_1782&PID_4D00"\nService=sprdvcom\n', encoding="utf-8"
    )
    pnputil_out = "Published Name: oem10.inf\nPublished Name: oem11.inf\nPublished Name: oem99.inf\n"
    res = parse_pnputil_unisoc_drivers(pnputil_out, inf_dir=tmp_path)
    assert res["installed"] is True
    assert res["has_4d00_winusb"] is True
    assert res["has_4d03_winusb"] is True
    assert set(res["winusb_infs"]) == {"oem10.inf", "oem11.inf"}
    assert res["conflicting_serial_infs"] == ["oem99.inf"]

    res_partial = parse_pnputil_unisoc_drivers("Published Name: oem10.inf\n", inf_dir=tmp_path)
    assert res_partial["installed"] is False
    assert res_partial["has_4d00_winusb"] is True
    assert res_partial["has_4d03_winusb"] is False


def test_parse_pnp_usb_devices_radar_matrix() -> None:
    """USB radar classifies stock Android, wrong model danger block, OpenWrt NCM error, BROM conflict, and disconnected."""
    # 1. Healthy stock F50 Pro MU3356
    st_ok = parse_pnp_usb_devices(
        [{"PNPDeviceID": r"USB\VID_19D2&PID_0246&MI_00\1", "Service": "usbrndis6", "ConfigManagerErrorCode": 0}],
        webui_info={"model_name": "MU3356", "cr_version": "MU3356V1.0.0B28"},
    )
    assert st_ok["state"] == "stock_android"
    assert st_ok["issues"] == []
    assert "MU3356" in st_ok["label"]

    # 2. Wrong model (e.g. MU300 regular F50) MUST trigger WRONG_DEVICE_MODEL error block
    st_wrong = parse_pnp_usb_devices(
        [{"PNPDeviceID": r"USB\VID_19D2&PID_0246&MI_00\1", "Service": "usbrndis6", "ConfigManagerErrorCode": 0}],
        webui_info={"model_name": "MU300", "cr_version": "MU300V1.0"},
    )
    assert any(i["code"] == "WRONG_DEVICE_MODEL" and i["severity"] == "error" for i in st_wrong["issues"])

    # 3. Stock RNDIS yellow exclamation mark
    st_rndis = parse_pnp_usb_devices(
        [{"PNPDeviceID": r"USB\VID_19D2&PID_0246&MI_00\1", "Service": "", "ConfigManagerErrorCode": 28}],
    )
    assert any(i["code"] == "STOCK_RNDIS_DRIVER_ERROR" for i in st_rndis["issues"])

    # 4. BROM device bound to wrong serial driver instead of WinUSB
    st_brom_bad = parse_pnp_usb_devices(
        [{"PNPDeviceID": r"USB\VID_1782&PID_4D00\1", "Service": "sprdvcom", "ConfigManagerErrorCode": 0}],
    )
    assert st_brom_bad["state"] == "brom"
    assert any(i["code"] == "BROM_DRIVER_NOT_WINUSB" for i in st_brom_bad["issues"])

    # 5. OpenWrt Win10 CDC-NCM yellow bang
    st_ow = parse_pnp_usb_devices(
        [{"InstanceId": r"USB\VID_1D6B&PID_0104&MI_00\1", "FriendlyName": "UsbNcm", "ConfigManagerErrorCode": 28}],
        openwrt_ssh_open=False,
    )
    assert st_ow["state"] == "openwrt"
    assert any(i["code"] == "OPENWRT_WIN10_NCM_ERROR" for i in st_ow["issues"])

    # 6. Disconnected
    st_none = parse_pnp_usb_devices([])
    assert st_none["state"] == "disconnected"
    assert st_none["issues"][0]["code"] == "DEVICE_DISCONNECTED"


def test_diagnose_failure_and_pii_sanitization() -> None:
    """Error classifier maps real failure modes to one-click repairs; diagnostic export scrubs all secrets/PII."""
    cases = [
        ("Unisoc BROM\nNo matching device found", "DRIVER_MISSING_ALL_FLAG", "install_drivers"),
        ("WebUIAuthError: WebUI login failed: {'result': '3'}", "WEBUI_BAD_PASSWORD", "focus_webui_password"),
        ("RuntimeError: Stock WebUI unreachable at http://192.168.0.1:8080", "WEBUI_UNREACHABLE", "repair_usb_network"),
        ("TimeoutError: Timed out waiting for SPRD4 handshake; Waiting for boot_diag", "BROM_HANDSHAKE_FAILED", "install_drivers"),
        ("ValueError: Target unit identity mismatch between backup and live device", "DEVICE_IDENTITY_MISMATCH", "new_workdir"),
        ("Missing ADB RSA public key required for Android root profile: adbkey.pub", "MISSING_ADB_KEY", "generate_adb_key"),
        ("URLError: <urlopen error [WinError 10054] connection reset>", "GITHUB_NETWORK_ERROR", "switch_mirror"),
        ("readback SHA-256 mismatch; wrote flash_failure_report.json", "FLASH_SAFE_STOP", "export_diag"),
    ]
    for raw_err, exp_code, exp_fix in cases:
        d = diagnose_failure(raw_err)
        assert d["code"] == exp_code
        assert d["fix_action"] == exp_fix

    fake_imei = "86" + "1234567890123"
    fake_iccid = "8986" + "0123456789012345"
    fake_user_path = "C:\\" + "Users\\SamplePerson\\workspace\\my-f50pro"
    raw = (
        f"cmd: --webui-password MySecretWeb123 --wifi-password WifiPass999 "
        f"path={fake_user_path} imei={fake_imei} iccid={fake_iccid}"
    )
    cleaned = sanitize_diagnostic_text(raw, secrets=["MySecretWeb123", "WifiPass999"])
    assert "MySecretWeb123" not in cleaned
    assert "WifiPass999" not in cleaned
    assert "SamplePerson" not in cleaned
    assert fake_imei not in cleaned
    assert fake_iccid not in cleaned


def test_github_updater_mirror_and_strict_sha256_verification(tmp_path: Path) -> None:
    """Updater validates HTTPS mirrors, enforces SHA256SUMS.txt, rejects tampered tarballs, and caches verified kits."""
    assert normalize_mirror_prefix("https://ghfast.top") == "https://ghfast.top/"
    with pytest.raises(ValueError, match="https://"):
        normalize_mirror_prefix("http://insecure.example")

    urls = build_candidate_urls("https://github.com/tanjiu90/f50pro-dualboot-kit/releases/download/v1.1.2/a.zip", "https://ghfast.top")
    assert urls == [
        "https://ghfast.top/https://github.com/tanjiu90/f50pro-dualboot-kit/releases/download/v1.1.2/a.zip",
        "https://github.com/tanjiu90/f50pro-dualboot-kit/releases/download/v1.1.2/a.zip",
    ]
    with patch.dict("os.environ", {"F50PRO_GITHUB_MIRROR": "https://ghfast.top"}):
        dl_urls = _build_download_urls("https://github.com/tanjiu90/f50pro-dualboot-kit/releases/download/v1.1.0/x.zip")
        assert dl_urls[0].startswith("https://ghfast.top/https://github.com/")
        assert dl_urls[1].startswith("https://github.com/")

    # Build a synthetic valid release source tar.gz
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for rel, body in (
            ("f50pro-dualboot-kit-v9.9.9/scripts/kit.py", b"print('ok')\n"),
            ("f50pro-dualboot-kit-v9.9.9/assets/release-manifest.json", b'{"release_tag":"v1.1.0","packs":{}}\n'),
        ):
            ti = tarfile.TarInfo(rel)
            ti.size = len(body)
            tf.addfile(ti, io.BytesIO(body))
    tar_bytes = buf.getvalue()
    tar_sha = hashlib.sha256(tar_bytes).hexdigest()
    sums_text = f"{tar_sha}  f50pro-dualboot-kit-v9.9.9-src.tar.gz\n"
    assert parse_sha256sums(sums_text)["f50pro-dualboot-kit-v9.9.9-src.tar.gz"] == tar_sha

    rel_info = {
        "tag": "v9.9.9",
        "assets": {
            "SHA256SUMS.txt": {"url": "https://github.com/tanjiu90/f50pro-dualboot-kit/releases/download/v9.9.9/SHA256SUMS.txt"},
            "f50pro-dualboot-kit-v9.9.9-src.tar.gz": {
                "url": "https://github.com/tanjiu90/f50pro-dualboot-kit/releases/download/v9.9.9/f50pro-dualboot-kit-v9.9.9-src.tar.gz"
            },
        },
    }

    # Tampered mirror payload MUST be rejected, falling back to clean direct GitHub bytes
    def fake_get(url: str, **kwargs):
        if url.endswith("SHA256SUMS.txt"):
            return sums_text.encode("utf-8")
        if url.startswith("https://ghfast.top/"):
            return b"TAMPERED_PAYLOAD"
        return tar_bytes

    store = tmp_path / "kit-src"
    with patch("gui.github_updater._http_get_bytes", side_effect=fake_get):
        res1 = download_and_verify_kit_release(rel_info, kit_store_dir=store, mirror_prefix="https://ghfast.top")
        assert res1["status"] == "downloaded"
        assert (Path(res1["kit_root"]) / "scripts" / "kit.py").is_file()

        # Second call uses verified local cache with zero HTTP calls
        res2 = download_and_verify_kit_release(rel_info, kit_store_dir=store, mirror_prefix="https://ghfast.top")
        assert res2["status"] == "cached"


def test_embedded_run_kit_worker_mode() -> None:
    """flasher_app.py --run-kit dispatches kit.py cleanly from a given kit root."""
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
    """On Windows, verify the Tkinter GUI initializes all 4 tabs and auto-troubleshooter banner cleanly."""
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

