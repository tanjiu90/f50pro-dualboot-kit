"""Cross-platform host resolution, selectable release downloads, route parsers, and Termux USB invocation tests."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from brom_backup import build_spd_invocation
from common import detect_host_platform, resolve_tool, write_json
from fetch_assets import list_available_packs, select_pack_keys
from host_network import (
    parse_linux_ip_routes,
    parse_macos_hardware_ports,
    parse_macos_netstat_routes,
)
from kit import main as kit_main
from provision_android import wait_for_adb_slot_a


def test_detect_host_platform_matrix() -> None:
    """detect_host_platform must distinguish win64, macos, linux-x64, linux-arm64, and android-arm64."""
    with patch("common.sys.platform", "win32"):
        assert detect_host_platform() == "win64"
    with patch("common.sys.platform", "darwin"):
        assert detect_host_platform() == "macos"
    with patch("common.sys.platform", "linux"), patch("common.os.environ", {"TERMUX_VERSION": "0.118.0"}):
        assert detect_host_platform() == "android-arm64"
    with (
        patch("common.sys.platform", "linux"),
        patch("common.os.environ", {}),
        patch("common.Path.is_dir", return_value=False),
        patch("common.Path.is_file", return_value=False),
        patch("common.platform.machine", return_value="aarch64"),
    ):
        assert detect_host_platform() == "linux-arm64"
    with (
        patch("common.sys.platform", "linux"),
        patch("common.os.environ", {}),
        patch("common.Path.is_dir", return_value=False),
        patch("common.Path.is_file", return_value=False),
        patch("common.platform.machine", return_value="x86_64"),
    ):
        assert detect_host_platform() == "linux-x64"


def test_resolve_tool_cross_platform(tmp_path: Path) -> None:
    """resolve_tool selects platform-appropriate spd_dump/adb including Termux su vs --usb-fd variants."""
    tools = tmp_path / "tools"
    pairs = {
        "win64": [
            tools / "host-tools-win64/spd_dump_251/spd_dump.exe",
            tools / "host-tools-win64/platform-tools/adb.exe",
        ],
        "linux-x64": [
            tools / "host-tools-linux-x64/bin/spd_dump",
            tools / "host-tools-linux-x64/platform-tools/adb",
        ],
        "linux-arm64": [
            tools / "host-tools-linux-arm64/bin/spd_dump",
        ],
        "macos": [
            tools / "host-tools-macos/bin/spd_dump",
            tools / "host-tools-macos/platform-tools/adb",
        ],
        "android-arm64": [
            tools / "host-tools-android-arm64/bin/spd_dump-su",
            tools / "host-tools-android-arm64/bin/spd_dump-termux-usb",
        ],
    }
    for paths in pairs.values():
        for p in paths:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"bin")

    assert resolve_tool("spd_dump", tools, platform_id="linux-x64").name == "spd_dump"
    assert resolve_tool("adb", tools, platform_id="linux-x64") == tools / "host-tools-linux-x64/platform-tools/adb"
    assert resolve_tool("spd_dump", tools, platform_id="linux-arm64").name == "spd_dump"
    assert resolve_tool("spd_dump", tools, platform_id="macos") == tools / "host-tools-macos/bin/spd_dump"
    assert (
        resolve_tool("spd_dump", tools, platform_id="android-arm64", prefer_variant="su").name == "spd_dump-su"
    )
    assert (
        resolve_tool("spd_dump", tools, platform_id="android-arm64", prefer_variant="termux-usb").name
        == "spd_dump-termux-usb"
    )


def test_select_pack_keys_filters() -> None:
    """Selectable download resolver honors host_platform, profile filter, OpenClash, and explicit pack keys."""
    manifest = {
        "release_tag": "v1.1.0",
        "base_url": "https://example.invalid/v1.1.0",
        "packs": {
            "openwrt_base": {"filename": "ow.tar.xz", "sha256": "a" * 64, "bytes": 100},
            "android_pkgs": {"filename": "an.zip", "sha256": "b" * 64, "bytes": 200},
            "openclash_offline": {"filename": "oc.tar.gz", "sha256": "c" * 64, "bytes": 300, "optional": True},
            "host_tools_win64": {"filename": "w.zip", "sha256": "d" * 64, "bytes": 400},
            "host_tools_linux_x64": {"filename": "lx.tar.gz", "sha256": "e" * 64, "bytes": 500},
            "host_tools_linux_arm64": {"filename": "la.tar.gz", "sha256": "f" * 64, "bytes": 600},
            "host_tools_macos": {"filename": "m.tar.gz", "sha256": "1" * 64, "bytes": 700},
            "host_tools_android_arm64": {"filename": "aa.tar.gz", "sha256": "2" * 64, "bytes": 800},
        },
    }
    assert select_pack_keys(manifest, host_platform="macos", profile="1-android-ufi", include_openclash=True) == [
        "android_pkgs",
        "host_tools_macos",
    ]
    assert select_pack_keys(
        manifest, host_platform="linux-arm64", profile="2-dual-stock-openwrt", include_openclash=False
    ) == ["openwrt_base", "host_tools_linux_arm64"]
    assert select_pack_keys(
        manifest, host_platform="android-arm64", profile="3-dual-full", include_openclash=True
    ) == ["openwrt_base", "android_pkgs", "openclash_offline", "host_tools_android_arm64"]
    assert len(select_pack_keys(manifest, host_platform="all", profile="all", include_openclash=True)) == 8
    assert select_pack_keys(
        manifest, explicit_packs=["host_tools_linux_x64,openwrt_base", "host_tools_linux_x64"]
    ) == ["host_tools_linux_x64", "openwrt_base"]
    with pytest.raises(ValueError, match="Unknown release pack"):
        select_pack_keys(manifest, explicit_packs=["nonexistent_pack"])

    rows = list_available_packs(manifest)
    assert any(r["pack"] == "host_tools_macos" and r["url"].endswith("/m.tar.gz") for r in rows)


def test_kit_list_packs_cli(capsys: pytest.CaptureFixture[str]) -> None:
    """kit.py fetch-assets --list-packs prints valid JSON catalog with URLs and SHA-256 digests."""
    rc = kit_main(["fetch-assets", "--list-packs"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert "packs" in payload and len(payload["packs"]) >= 3


def test_linux_and_macos_host_network_parsers() -> None:
    """Linux ip-json and macOS netstat/networksetup parsers catch USB CDC-NCM / RNDIS gateway leaks."""
    v4_leak = json.dumps([{"dst": "default", "gateway": "192.168.77.1", "dev": "usb0", "metric": 100}])
    v4_clean = json.dumps([{"dst": "default", "gateway": "192.168.1.1", "dev": "wlan0", "metric": 600}])
    res_l = parse_linux_ip_routes(v4_leak, "[]", {"usb0"})
    res_c = parse_linux_ip_routes(v4_clean, "[]", {"usb0"})
    assert res_l["usb_default_route_leak"] is True and len(res_l["leaks"]) == 1
    assert res_c["usb_default_route_leak"] is False

    hw = """Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 11:22:33:44:55:66

Hardware Port: CDC NCM
Device: en9
Ethernet Address: aa:bb:cc:dd:ee:ff
"""
    ports = parse_macos_hardware_ports(hw)
    assert ports[1]["port"] == "CDC NCM" and ports[1]["device"] == "en9"

    mac_v4_leak = """Routing tables
Destination        Gateway            Flags               Netif Expire
default            192.168.77.1       UGScg                 en9
default            192.168.1.1        UGScIg                en0
"""
    mac_v4_clean = """Routing tables
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
"""
    assert parse_macos_netstat_routes(mac_v4_leak, "", {"en9"})["usb_default_route_leak"] is True
    assert parse_macos_netstat_routes(mac_v4_clean, "", {"en9"})["usb_default_route_leak"] is False


def test_build_spd_invocation_cross_platform(tmp_path: Path) -> None:
    """build_spd_invocation generates proper sudo, su, and termux-usb (--usb-fd) command arrays."""
    tools = tmp_path / "tools"
    (tools / "host-tools-macos/bin").mkdir(parents=True)
    (tools / "host-tools-macos/bin/spd_dump").write_bytes(b"mac")
    (tools / "host-tools-android-arm64/bin").mkdir(parents=True)
    (tools / "host-tools-android-arm64/bin/spd_dump-su").write_bytes(b"su")
    (tools / "host-tools-android-arm64/bin/spd_dump-termux-usb").write_bytes(b"fd")

    base_args = ["--wait", "120", "--kickto", "2", "--verbose", "1", "r", "all", "reset"]
    with patch("brom_backup.detect_host_platform", return_value="macos"):
        cmd_mac, meta_mac = build_spd_invocation(tools, base_args, spd_mode="sudo")
        assert cmd_mac[0] == "sudo" and meta_mac["mode"] == "sudo" and "--kickto" in cmd_mac

    with patch("brom_backup.detect_host_platform", return_value="android-arm64"):
        cmd_su, meta_su = build_spd_invocation(tools, base_args, spd_mode="su")
        assert cmd_su[:2] == ["su", "-c"] and "--kickto 2" in cmd_su[2] and meta_su["mode"] == "su"

        with patch("brom_backup.shutil.which", return_value="/data/data/com.termux/files/usr/bin/termux-usb"):
            cmd_fd, meta_fd = build_spd_invocation(
                tools, base_args, spd_mode="termux-usb", usb_dev="/dev/bus/usb/001/002"
            )
            assert meta_fd["mode"] == "termux-usb"
            assert meta_fd["requires_pre_autodloader"] is True
            assert cmd_fd[1] == "-e" and "--usb-fd" in cmd_fd[2]
            assert "--kickto" not in cmd_fd[2] and "--wait" not in cmd_fd[2]
            assert cmd_fd[3] == "/dev/bus/usb/001/002"


def test_wireless_adb_connect_for_nonroot_termux(tmp_path: Path) -> None:
    """wait_for_adb_slot_a connects over TCP when serial contains host:port (e.g. 192.168.0.1:5555)."""
    seen: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        seen.append(cmd)
        if "get-state" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="device\n", stderr="")
        if "ro.boot.slot_suffix" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="_a\n", stderr="")
        if "sys.boot_completed" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="1\n", stderr="")
        if "id -u" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="0\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    with patch("provision_android.subprocess.run", side_effect=fake_run):
        slot = wait_for_adb_slot_a(tmp_path / "adb", timeout=5, serial="192.168.0.1:5555")
    assert slot == "_a"
    assert any(c[-2:] == ["connect", "192.168.0.1:5555"] for c in seen)
