"""Fault-injection and security-remediation tests covering P0-1 through P0-6."""
from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from brom_backup import parse_partition_xml
from build_images import build_profile
from common import sha256_bytes
from flash_images import _SpdSession, execute_flash


class _FakePopen:
    """Minimal Popen double capturing stdin lines sent to spd_dump."""

    def __init__(self, stdout_lines: list[str] | None = None):
        self.stdin = io.StringIO()
        self.stdout = iter(stdout_lines or [])
        self._rc: int | None = None
        self.terminated = False

    def poll(self):
        return self._rc

    def terminate(self):
        self.terminated = True
        self._rc = -15

    def wait(self, timeout=None):
        if self._rc is None:
            self._rc = 0
        return self._rc


def test_p0_1_flash_failure_never_reboots_or_switches_slot(
    synthetic_env: dict[str, Path], tmp_path: Path
) -> None:
    """P0-1: Readback mismatch, GPT mismatch, USB disconnect, and write timeout must NOT call reset or wof."""
    good_tbl = list(parse_partition_xml(synthetic_env["backup_dir"] / "partition_list.xml").items())

    # Scenario 1: Readback SHA mismatch AFTER trustos_a succeeds on pre_read -> init_boot_a fails readback
    out1 = synthetic_env["out_dir"] / "p0_1_rb"
    plan1 = build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="1-android-ufi",
        out_dir=out1,
        tools_dir=synthetic_env["tools_dir"],
        adb_pubkey_path=synthetic_env["adb_pubkey"],
    )
    tos_sha = plan1["operations"][0]["sha256"]
    tos_bytes = Path(plan1["operations"][0]["file"]).read_bytes()

    sess1 = MagicMock()
    sess1.table.return_value = good_tbl

    def _read_sc1(part: str, sz: int, fname: str) -> bytes:
        if "_id_probe" in fname:
            return (synthetic_env["backup_dir"] / part).read_bytes()[:sz]
        if part == "trustos_a":
            return tos_bytes  # already verified!
        return b"\xaa" * sz  # init_boot_a differs pre & fails readback

    sess1.read_part.side_effect = _read_sc1
    with patch("flash_images.resolve_tool", return_value=tmp_path / "spd_dump"), patch(
        "flash_images._SpdSession", return_value=sess1
    ):
        with pytest.raises(RuntimeError, match="Readback SHA mismatch on init_boot_a"):
            execute_flash(out1 / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], execute=True)

    sess1.close.assert_called_once_with(reboot=False)
    sent1 = [c.args[0][0] for c in sess1.cmd.call_args_list]
    assert "wof" not in sent1
    state1 = json.loads((out1 / "flash-run" / "flash_state.json").read_text(encoding="utf-8"))
    assert state1["status"] == "FLASH_FAILED"
    assert state1["reset_sent"] is False
    assert state1["slot_switched"] is False
    assert state1["auto_rollback_attempted"] is False
    assert state1["failed_stage"] == "readback:init_boot_a"
    assert any(p["partition"] == "trustos_a" and p["sha256"] == tos_sha for p in state1["verified_partitions"])
    assert any(p["partition"] == "init_boot_a" for p in state1["pending_operations"])
    assert state1["diagnostic_channel"]["probed"] is True
    assert state1["diagnostic_channel"]["responsive"] is True

    # Scenario 2: Live GPT mismatch -> aborts before ANY write or reset
    out2 = synthetic_env["out_dir"] / "p0_1_gpt"
    build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="2-dual-stock-openwrt",
        out_dir=out2,
        tools_dir=synthetic_env["tools_dir"],
    )
    bad_tbl = [(good_tbl[0][0], good_tbl[0][1] + 4096), *good_tbl[1:]]
    sess2 = MagicMock()
    sess2.table.return_value = bad_tbl
    with patch("flash_images.resolve_tool", return_value=tmp_path / "spd_dump"), patch(
        "flash_images._SpdSession", return_value=sess2
    ):
        with pytest.raises(RuntimeError, match="Live GPT partition table differs"):
            execute_flash(out2 / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], execute=True)
    sess2.close.assert_called_once_with(reboot=False)
    sess2.cmd.assert_not_called()
    state2 = json.loads((out2 / "flash-run" / "flash_state.json").read_text(encoding="utf-8"))
    assert state2["reset_sent"] is False and state2["failed_stage"] == "precheck_gpt"

    # Scenario 3: USB disconnect mid-write (LIBUSB_ERROR_NO_DEVICE) -> stops writes, skips diagnostic probe, no reset
    out3 = synthetic_env["out_dir"] / "p0_1_usb"
    build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="2-dual-stock-openwrt",
        out_dir=out3,
        tools_dir=synthetic_env["tools_dir"],
    )
    sess3 = MagicMock()
    sess3.table.return_value = good_tbl

    def _dev_a_then_zeros(part: str, sz: int, fname: str) -> bytes:
        if "_id_probe" in fname:
            return (synthetic_env["backup_dir"] / part).read_bytes()[:sz]
        return b"\x00" * sz

    sess3.read_part.side_effect = _dev_a_then_zeros
    sess3.cmd.side_effect = RuntimeError("Fatal spd_dump output: LIBUSB_ERROR_NO_DEVICE")
    with patch("flash_images.resolve_tool", return_value=tmp_path / "spd_dump"), patch(
        "flash_images._SpdSession", return_value=sess3
    ):
        with pytest.raises(RuntimeError, match="LIBUSB_ERROR_NO_DEVICE"):
            execute_flash(out3 / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], execute=True)
    sess3.close.assert_called_once_with(reboot=False)
    assert sess3.cmd.call_count == 1
    assert sess3.table.call_count == 1  # skipped extra diag probe after USB transport loss
    state3 = json.loads((out3 / "flash-run" / "flash_state.json").read_text(encoding="utf-8"))
    assert state3["reset_sent"] is False
    assert state3["diagnostic_channel"]["transport_lost"] is True

    # Scenario 4: Write timeout + real _SpdSession.close(reboot=False) never writes "reset" to stdin
    out4 = synthetic_env["out_dir"] / "p0_1_to"
    build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="2-dual-stock-openwrt",
        out_dir=out4,
        tools_dir=synthetic_env["tools_dir"],
    )
    sess4 = MagicMock()
    sess4.table.return_value = good_tbl
    sess4.read_part.side_effect = _dev_a_then_zeros
    sess4.cmd.side_effect = TimeoutError("Timed out waiting for Write Part Done")
    with patch("flash_images.resolve_tool", return_value=tmp_path / "spd_dump"), patch(
        "flash_images._SpdSession", return_value=sess4
    ):
        with pytest.raises(TimeoutError, match="Timed out waiting"):
            execute_flash(out4 / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], execute=True)
    sess4.close.assert_called_once_with(reboot=False)
    state4 = json.loads((out4 / "flash-run" / "flash_state.json").read_text(encoding="utf-8"))
    assert state4["reset_sent"] is False and state4["slot_switched"] is False

    # Verify _SpdSession.close(reboot=False) never sends "reset" to spd_dump stdin
    fake_p = _FakePopen()
    with patch("flash_images.subprocess.Popen", return_value=fake_p):
        real_sess = _SpdSession(tmp_path / "spd_dump", out4 / "stdin_check", wait_sec=5)
        real_sess.close(reboot=False)
    assert '"reset"' not in fake_p.stdin.getvalue()
    assert fake_p.terminated is True


def test_p0_2_swapped_identical_model_device_rejected(
    synthetic_env: dict[str, Path], tmp_path: Path
) -> None:
    """P0-2: Two units with identical GPT and identical firmware hashes must still be distinguished and rejected if swapped."""
    from common import write_json
    from flash_images import validate_plan_safety

    dev_a_backup = synthetic_env["backup_dir"]
    good_tbl = list(parse_partition_xml(dev_a_backup / "partition_list.xml").items())
    out_a = synthetic_env["out_dir"] / "p0_2_deva"
    plan_a = build_profile(
        backup_dir=dev_a_backup,
        profile_id="2-dual-stock-openwrt",
        out_dir=out_a,
        tools_dir=synthetic_env["tools_dir"],
        board_id="6",
        usb_topology={"bus": 1, "port_path": "1-3", "serial": "SYNTH-DEV-A"},
    )

    # Device B has identical GPT & identical boot/vendor_boot/trustos firmware, only ztecfg/persist differ!
    mib = 1 << 20
    dev_b_ztecfg = (b"SYNTH_UNIT_B_ZTECFG!" * ((mib // 20) + 1))[:mib]
    dev_b_persist = (b"SYNTH_UNIT_B_PERSIST!" * ((mib // 21) + 1))[:mib]

    def _read_device_b(part: str, sz: int, fname: str) -> bytes:
        if part == "ztecfg":
            return dev_b_ztecfg[:sz]
        if part == "persist":
            return dev_b_persist[:sz]
        return (dev_a_backup / part).read_bytes()[:sz]

    sess_b = MagicMock()
    sess_b.table.return_value = good_tbl
    sess_b.read_part.side_effect = _read_device_b
    with patch("flash_images.resolve_tool", return_value=tmp_path / "spd_dump"), patch(
        "flash_images._SpdSession", return_value=sess_b
    ):
        with pytest.raises(RuntimeError, match="Target device identity mismatch"):
            execute_flash(out_a / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], execute=True)

    sess_b.cmd.assert_not_called()
    sess_b.close.assert_called_once_with(reboot=False)
    state = json.loads((out_a / "flash-run" / "flash_state.json").read_text(encoding="utf-8"))
    assert state["failed_stage"] == "precheck_identity"
    assert state["reset_sent"] is False

    # Same Device A hardware, but board_id or USB topology mismatch must ALSO abort before writes
    sess_a = MagicMock()
    sess_a.table.return_value = good_tbl
    sess_a.read_part.side_effect = lambda part, sz, fname: (dev_a_backup / part).read_bytes()[:sz]
    with patch("flash_images.resolve_tool", return_value=tmp_path / "spd_dump"), patch(
        "flash_images._SpdSession", return_value=sess_a
    ):
        with pytest.raises(RuntimeError, match="Target board_id mismatch"):
            execute_flash(out_a / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], execute=True, board_id="1")
        with pytest.raises(RuntimeError, match="Target USB topology mismatch"):
            execute_flash(
                out_a / "flash_plan.json",
                tools_dir=synthetic_env["tools_dir"],
                execute=True,
                usb_topology={"bus": 2, "port_path": "2-4", "serial": "SYNTH-DEV-B"},
            )

    # Zero PII in plan & hardware_facts: raw partition strings never leaked into JSON artifacts
    plan_txt = (out_a / "flash_plan.json").read_text(encoding="utf-8")
    facts_txt = (out_a / "hardware_facts.json").read_text(encoding="utf-8")
    assert "SYNTH_UNIT_A_ZTECFG" not in plan_txt and "SYNTH_UNIT_A_PERSIST" not in plan_txt
    assert "SYNTH_UNIT_A_ZTECFG" not in facts_txt and "SYNTH_UNIT_A_PERSIST" not in facts_txt

    # Weak identity (all-zero ztecfg/persist) must refuse automatic flash without confirm_weak_identity
    mib = 1 << 20
    (dev_a_backup / "ztecfg").write_bytes(b"\x00" * mib)
    (dev_a_backup / "persist").write_bytes(b"\x00" * mib)
    out_weak = synthetic_env["out_dir"] / "p0_2_weak"
    weak_plan = build_profile(
        backup_dir=dev_a_backup,
        profile_id="2-dual-stock-openwrt",
        out_dir=out_weak,
        tools_dir=synthetic_env["tools_dir"],
    )
    assert weak_plan["device_identity"]["identity_strength"] == "weak"
    sess_w = MagicMock()
    sess_w.table.return_value = good_tbl
    with patch("flash_images.resolve_tool", return_value=tmp_path / "spd_dump"), patch(
        "flash_images._SpdSession", return_value=sess_w
    ):
        with pytest.raises(RuntimeError, match="Target device identity is weak/insufficient"):
            execute_flash(out_weak / "flash_plan.json", tools_dir=synthetic_env["tools_dir"], execute=True)
    sess_w.cmd.assert_not_called()

    # Profile explicit allowlist rejects unapproved partition / wrong op / wrong offset / oversized write
    dummy = tmp_path / "payload.bin"
    dummy.write_bytes(b"X" * 64)
    tamper_allow = {
        "profile": "2-dual-stock-openwrt",
        "operations": [{"op": "w", "partition": "recovery_b", "file": str(dummy), "size_bytes": 64, "sha256": sha256_bytes(b"X" * 64)}],
    }
    with pytest.raises(ValueError, match="explicit allowlist"):
        validate_plan_safety(tamper_allow)

    tamper_offset = {
        "profile": "2-dual-stock-openwrt",
        "operations": [{"op": "wof", "partition": "misc", "offset": 0, "file": str(dummy), "size_bytes": 32, "sha256": sha256_bytes(b"X" * 64)}],
    }
    with pytest.raises(ValueError, match="Offset 0 not permitted"):
        validate_plan_safety(tamper_offset)


def test_p0_3_targeted_nic_selection_ignores_phone_tether_usb_dock_and_wifi_192_168_0_1(tmp_path: Path) -> None:
    """P0-3: Correlate ONLY F50 Pro USB interface; ignore phone tethering, USB dock, and normal 192.168.0.1 Wi-Fi."""
    from host_network import (
        audit_default_routes,
        correlate_macos_net_candidates,
        isolate_usb_rndis_adapter,
        parse_linux_ip_routes,
        parse_macos_netstat_routes,
        parse_macos_network_service_order,
        parse_macos_spusb_net_devices,
        restore_network_snapshot,
        select_target_usb_adapters,
    )

    # 1. Mixed USB devices simultaneously connected: F50 Pro (1d6b:0104) + Phone Tether (18d1:4ee3) + USB Dock (0bda:8153)
    cands = [
        {"name": "usb0", "device": "usb0", "vid": "18d1", "pid": "4ee3", "desc": "Remote NDIS based Internet Sharing Device", "port_path": "1-1"},
        {"name": "enx00e04c", "device": "enx00e04c", "vid": "0bda", "pid": "8153", "desc": "USB 10/100/1000 LAN", "port_path": "1-2"},
        {"name": "usb1", "device": "usb1", "vid": "1d6b", "pid": "0104", "desc": "CDC NCM", "port_path": "1-4", "serial": "F50-SERIAL"},
    ]
    sel = select_target_usb_adapters(cands)
    assert sel["ambiguous"] is False
    assert [t["name"] for t in sel["targets"]] == ["usb1"]
    assert len(sel["ignored"]) == 2

    # 2. Ambiguous: two uncorrelated F50 Pro adapters -> must refuse bulk mutation without executing system commands
    cands_two = [
        {"name": "usb1", "device": "usb1", "vid": "1d6b", "pid": "0104", "port_path": "1-4"},
        {"name": "usb2", "device": "usb2", "vid": "1d6b", "pid": "0104", "port_path": "1-5"},
    ]
    assert select_target_usb_adapters(cands_two)["ambiguous"] is True
    with (
        patch("host_network.detect_host_platform", return_value="linux-x64"),
        patch("host_network._detect_linux_net_candidates", return_value=cands_two),
        patch("host_network._run_priv_posix") as priv_spy,
    ):
        with pytest.raises(RuntimeError, match="Multiple correlated F50 Pro USB interfaces"):
            isolate_usb_rndis_adapter()
        priv_spy.assert_not_called()

    # 3. Normal Wi-Fi via 192.168.0.1 must NEVER be falsely flagged as an F50 Pro leak on Windows/Linux/macOS
    win_wifi_192_0_1 = json.dumps({
        "ipv4_default": [{"ifIndex": 7, "InterfaceAlias": "Wi-Fi", "NextHop": "192.168.0.1", "RouteMetric": 25}],
        "ipv6_default": [],
        "rndis_adapters": [{"ifIndex": 42, "Name": "F50-USB", "PnpDeviceID": "USB\\VID_1D6B&PID_0104\\1", "Status": "Up"}],
    })
    with patch("host_network.sys.platform", "win32"), patch("host_network._ps", return_value=win_wifi_192_0_1):
        assert audit_default_routes()["usb_default_route_leak"] is False

    lin_wifi_192_0_1 = json.dumps([{"dst": "default", "gateway": "192.168.0.1", "dev": "wlan0", "metric": 600}])
    assert parse_linux_ip_routes(lin_wifi_192_0_1, "[]", {"usb1"})["usb_default_route_leak"] is False

    mac_wifi_192_0_1 = "default 192.168.0.1 UGScg en0\n"
    assert parse_macos_netstat_routes(mac_wifi_192_0_1, "", {"en9"})["usb_default_route_leak"] is False

    # 4. macOS custom-renamed Network Service vs Hardware Port vs BSD Device + SPUSB correlation
    svc_order = """An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(2) My Office Dock
(Hardware Port: USB 10/100/1000 LAN, Device: en5)

(3) Custom F50 Slot
(Hardware Port: CDC NCM, Device: en9)
"""
    spusb = json.dumps({
        "SPUSBDataType": [
            {
                "_items": [
                    {"_name": "USB 10/100/1000 LAN", "vendor_id": "0x0bda", "product_id": "0x8153", "bsd_name": "en5", "location_id": "0x01100000"},
                    {"_name": "CDC NCM", "vendor_id": "0x1d6b", "product_id": "0x0104", "bsd_name": "en9", "serial_num": "F50MAC1", "location_id": "0x01200000"},
                ]
            }
        ]
    })
    mac_cands = correlate_macos_net_candidates(
        parse_macos_network_service_order(svc_order),
        parse_macos_spusb_net_devices(spusb),
    )
    mac_sel = select_target_usb_adapters(mac_cands)
    assert len(mac_sel["targets"]) == 1
    assert mac_sel["targets"][0]["network_service"] == "Custom F50 Slot"
    assert mac_sel["targets"][0]["hardware_port"] == "CDC NCM"
    assert mac_sel["targets"][0]["device"] == "en9"

    # 5. Pre-change snapshot & non-clobber restore when user modified interface afterwards
    snap_path = tmp_path / "net_snap.json"
    snap_path.write_text(
        json.dumps({
            "applied_static_ip": "192.168.77.12",
            "entries": [{"platform": "linux", "iface": "usb1", "nm_connection": "F50", "nm_state": {"ipv4.method": "auto"}}],
        }),
        encoding="utf-8",
    )
    user_edited_state = {
        "platform": "linux",
        "iface": "usb1",
        "ip_addr_json": [{"ifname": "usb1", "addr_info": [{"local": "10.0.0.5"}]}],
        "nm_connection": "F50",
        "nm_state": {},
    }
    with patch("host_network._snapshot_linux_iface", return_value=user_edited_state), patch(
        "host_network._run_priv_posix"
    ) as priv_spy2:
        rest = restore_network_snapshot(snap_path, force=False)
    assert rest["results"][0]["status"] == "skipped_user_modified"
    priv_spy2.assert_not_called()

    # 6. Explicit internet-exit mode must not strip default gateway
    res_inet = isolate_usb_rndis_adapter(mode="internet-exit")
    assert res_inet["mode"] == "internet-exit" and res_inet["isolated"] == []


def test_p0_4_no_forced_permanent_rndis_and_safe_usb_mode_transition(
    synthetic_env: dict[str, Path], tmp_path: Path
) -> None:
    """P0-4: Default preserves working ncm/ecm/rndis; explicit switch handles disconnect, timeout, and device swap."""
    from common import build_trial_bcab
    from provision_openwrt import (
        UsbNetModeSwitchTimeoutError,
        provision_openwrt,
        resolve_host_usb_net_plan,
    )

    # 1. Host-adapter decisions across macOS, Linux, Android, and Windows default to preserving working modes
    for plat in ("macos", "linux-x64", "linux-arm64", "android-arm64", "win64"):
        for cur in ("ncm", "ecm", "rndis"):
            dec = resolve_host_usb_net_plan(host_platform=plat, current_mode=cur, requested_mode="auto")
            assert dec["switch_required"] is False
            assert dec["permanent"] is False
            assert dec["final_usb_net_mode"] == cur

    # Explicit temporary vs persistent transitions clearly tracked
    tmp_sw = resolve_host_usb_net_plan(host_platform="win64", current_mode="ncm", requested_mode="rndis", persist_mode=False)
    assert tmp_sw["switch_required"] is True and tmp_sw["permanent"] is False and tmp_sw["expected_disconnect"] is True
    perm_sw = resolve_host_usb_net_plan(host_platform="win64", current_mode="ncm", requested_mode="rndis", persist_mode=True)
    assert perm_sw["switch_required"] is True and perm_sw["permanent"] is True

    # Helper to construct realistic fake SSH session + known-good BCAB block
    misc_orig = (synthetic_env["backup_dir"] / "misc").read_bytes()[2048:2080]
    bcab_b = build_trial_bcab(misc_orig, "b", tries=6)
    tools = synthetic_env["tools_dir"]
    (tools / "openwrt-base" / "mu300-keys").write_bytes(b"KEYS")

    def _make_fake_ssh(usb_mode: str = "ncm", board_id: str = "6", host_hash: str = "aaa111", *, disconnect_on_setnet: bool = False):
        ssh = MagicMock()
        ssh.executed_cmds = []

        def _fake_ssh_run(client, cmd, *, check=True, timeout=60.0):
            client.executed_cmds.append(cmd)
            if "device-usb set-net" in cmd and disconnect_on_setnet:
                raise EOFError("Simulated expected USB gadget re-enumeration disconnect")
            if "board_id=" in cmd and "usb_mode=" in cmd:
                return 0, f"board_id={board_id}\nusb_mode={usb_mode}\nhost_hash={host_hash}\n", ""
            if "f50pro-rootfs-grow.py" in cmd:
                return 0, json.dumps({"filesystem_bytes": 2147483648}), ""
            return 0, "", ""

        sftp = MagicMock()
        ssh.open_sftp.return_value = sftp
        return ssh, _fake_ssh_run

    # 2. Live provision on macOS with NCM active must preserve NCM and NEVER invoke set-net rndis permanent 1
    out_ncm = tmp_path / "ow_ncm"
    ssh_ncm, spy_ncm = _make_fake_ssh(usb_mode="ncm", board_id="6", host_hash="unit_a_hash")
    with (
        patch("provision_openwrt.detect_host_platform", return_value="macos"),
        patch("provision_openwrt.wait_for_openwrt_ssh", return_value=ssh_ncm),
        patch("provision_openwrt.ssh_run", side_effect=spy_ncm),
        patch("provision_openwrt._ensure_board6_card_patch", return_value="card_sha"),
        patch("provision_openwrt._ensure_capacity_ui", return_value={"ui": "ok"}),
        patch("provision_openwrt._ensure_5s_buttons", return_value={"long_action": "system-switch"}),
        patch("provision_openwrt.sftp_get_bytes", return_value=bcab_b),
    ):
        res_ncm = provision_openwrt(
            profile_id="2-dual-stock-openwrt",
            tools_dir=tools,
            out_dir=out_ncm,
            reboot_after=False,
        )
    assert res_ncm["install_usb_net_mode"] == "ncm"
    assert res_ncm["final_usb_net_mode"] == "ncm"
    assert not any("set-net rndis" in c for c in ssh_ncm.executed_cmds)
    assert not any("u30pro.usb.mode='rndis'" in c for c in ssh_ncm.executed_cmds)

    # 3. Explicit temporary switch ncm -> rndis handles expected USB disconnect cleanly and reconnects to same unit
    out_sw = tmp_path / "ow_switch"
    ssh_pre, spy_pre = _make_fake_ssh(usb_mode="ncm", board_id="6", host_hash="unit_a_hash", disconnect_on_setnet=True)
    ssh_post, spy_post = _make_fake_ssh(usb_mode="rndis", board_id="6", host_hash="unit_a_hash")
    ssh_seq = iter([ssh_pre, ssh_post])

    def _dispatch_run(client, cmd, *, check=True, timeout=60.0):
        return spy_pre(client, cmd, check=check, timeout=timeout) if client is ssh_pre else spy_post(client, cmd, check=check, timeout=timeout)

    with (
        patch("provision_openwrt.detect_host_platform", return_value="win64"),
        patch("provision_openwrt.wait_for_openwrt_ssh", side_effect=lambda *a, **k: next(ssh_seq)),
        patch("provision_openwrt.ssh_run", side_effect=_dispatch_run),
        patch("provision_openwrt.time.sleep"),
        patch("provision_openwrt._ensure_board6_card_patch", return_value="card_sha"),
        patch("provision_openwrt._ensure_capacity_ui", return_value={"ui": "ok"}),
        patch("provision_openwrt._ensure_5s_buttons", return_value={"long_action": "system-switch"}),
        patch("provision_openwrt.sftp_get_bytes", return_value=bcab_b),
    ):
        res_sw = provision_openwrt(
            profile_id="2-dual-stock-openwrt",
            usb_net_mode="rndis",
            usb_net_persist=False,
            tools_dir=tools,
            out_dir=out_sw,
            reboot_after=False,
        )
    assert res_sw["install_usb_net_mode"] == "ncm"
    assert res_sw["final_usb_net_mode"] == "rndis"
    assert res_sw["usb_net_transition"]["expected_disconnect_observed"] is True
    assert res_sw["usb_net_transition"]["permanent"] is False
    assert res_sw["usb_net_transition"]["reconnected"] is True

    # 4. Timeout during re-enumeration raises UsbNetModeSwitchTimeoutError cleanly
    out_to = tmp_path / "ow_to"
    ssh_pre2, spy_pre2 = _make_fake_ssh(usb_mode="ncm", board_id="6", host_hash="unit_a_hash", disconnect_on_setnet=True)
    call_cnt = {"n": 0}

    def _wait_then_timeout(*a, **k):
        call_cnt["n"] += 1
        if call_cnt["n"] == 1:
            return ssh_pre2
        raise TimeoutError("no interface back")

    with (
        patch("provision_openwrt.detect_host_platform", return_value="win64"),
        patch("provision_openwrt.wait_for_openwrt_ssh", side_effect=_wait_then_timeout),
        patch("provision_openwrt.ssh_run", side_effect=spy_pre2),
        patch("provision_openwrt.time.sleep"),
        patch("provision_openwrt._ensure_board6_card_patch", return_value="card_sha"),
        patch("provision_openwrt._ensure_capacity_ui", return_value={"ui": "ok"}),
        patch("provision_openwrt._ensure_5s_buttons", return_value={"long_action": "system-switch"}),
    ):
        with pytest.raises(UsbNetModeSwitchTimeoutError, match="Timed out waiting for F50 Pro USB re-enumeration"):
            provision_openwrt(
                profile_id="2-dual-stock-openwrt",
                usb_net_mode="rndis",
                tools_dir=tools,
                out_dir=out_to,
                reboot_after=False,
            )

    # 5. Swapped device during USB re-enumeration must abort cleanly
    out_swap = tmp_path / "ow_swap"
    ssh_pre3, spy_pre3 = _make_fake_ssh(usb_mode="ncm", board_id="6", host_hash="unit_a_hash", disconnect_on_setnet=True)
    ssh_wrong, spy_wrong = _make_fake_ssh(usb_mode="rndis", board_id="1", host_hash="unit_b_hash")
    seq3 = iter([ssh_pre3, ssh_wrong])

    def _dispatch3(client, cmd, *, check=True, timeout=60.0):
        return spy_pre3(client, cmd, check=check, timeout=timeout) if client is ssh_pre3 else spy_wrong(client, cmd, check=check, timeout=timeout)

    with (
        patch("provision_openwrt.detect_host_platform", return_value="win64"),
        patch("provision_openwrt.wait_for_openwrt_ssh", side_effect=lambda *a, **k: next(seq3)),
        patch("provision_openwrt.ssh_run", side_effect=_dispatch3),
        patch("provision_openwrt.time.sleep"),
        patch("provision_openwrt._ensure_board6_card_patch", return_value="card_sha"),
        patch("provision_openwrt._ensure_capacity_ui", return_value={"ui": "ok"}),
        patch("provision_openwrt._ensure_5s_buttons", return_value={"long_action": "system-switch"}),
    ):
        with pytest.raises(RuntimeError, match="Target device swapped"):
            provision_openwrt(
                profile_id="2-dual-stock-openwrt",
                usb_net_mode="rndis",
                tools_dir=tools,
                out_dir=out_swap,
                reboot_after=False,
            )


def test_p0_5_auth_context_verify_verdicts_and_preflight_gate(
    synthetic_env: dict[str, Path], tmp_path: Path
) -> None:
    """P0-5: AuthContext generation/redaction, slot parsing without wifi_device spoofing, profile-aware PASS/FAIL/NOT_TESTED/NOT_APPLICABLE, non-zero exit codes, and strict preflight gate."""
    from common import build_trial_bcab, resolve_auth_context
    from kit import assert_preflight_ready
    from kit import main as kit_main
    from provision_openwrt import provision_openwrt
    from verify_e2e import _parse_openwrt_boot_evidence, evaluate_e2e_checks, verify_environment

    tools = synthetic_env["tools_dir"]
    bcab_b = build_trial_bcab((synthetic_env["backup_dir"] / "misc").read_bytes()[2048:2080], "b", tries=6)

    # 1. Generated password flows via AuthContext & openwrt-credentials.json into verify without leaking raw password
    out_cred = tmp_path / "cred_flow"
    ssh_ok = MagicMock()
    ssh_ok.close = MagicMock()
    seen_passwords: list[tuple[str, ...]] = []

    def _run_ow(client, cmd, *, check=True, timeout=60.0):
        if "cat /proc/driver/board_id" in cmd and "model=" not in cmd:
            return 0, "6", ""
        if "model=" in cmd:
            return (
                0,
                "model=f50pro\nboard_id=6\nwifi_device=phy0-ap0\nopenwrt_id=OpenWrt\ncmdline=console=ttyS0 androidboot.slot_suffix=_b\nbootargs=\nbutton_long=system-switch\n/dev/root 100 50 50 50% /\n",
                "",
            )
        if "uci -q get u30pro.usb.mode" in cmd or "device-usb" in cmd:
            return 0, "ncm", ""
        if "dd if=/dev/block/by-name/misc" in cmd:
            return 0, "", ""
        if "/etc/mu300/model" in cmd and "sha256sum" not in cmd:
            return 0, "f50pro", ""
        if "sha256sum /etc/dropbear" in cmd:
            return 0, "unit_hash_a  /etc/dropbear/dropbear_ed25519_host_key", ""
        if "f50pro-rootfs-grow.py" in cmd:
            return 0, '{"grown": true}', ""
        return 0, "", ""

    def _fake_connect(host, *, username="root", passwords=("", "root"), timeout=5.0):
        seen_passwords.append(tuple(passwords))
        return ssh_ok

    class _FakeResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    with (
        patch("provision_openwrt.detect_host_platform", return_value="win64"),
        patch("provision_openwrt.wait_for_openwrt_ssh", return_value=ssh_ok),
        patch("provision_openwrt.ssh_run", side_effect=_run_ow),
        patch("provision_openwrt.time.sleep"),
        patch("provision_openwrt._ensure_board6_card_patch", return_value="card_sha"),
        patch("provision_openwrt._ensure_capacity_ui", return_value={"ui": "ok"}),
        patch("provision_openwrt._ensure_5s_buttons", return_value={"long_action": "system-switch"}),
        patch("provision_openwrt.sftp_get_bytes", return_value=bcab_b),
    ):
        prov = provision_openwrt(
            profile_id="3-dual-full",
            generate_password=True,
            tools_dir=tools,
            out_dir=out_cred,
            isolate_host=False,
            reboot_after=False,
        )

    cred_path = Path(prov["credentials_file"])
    generated_pw = json.loads(cred_path.read_text(encoding="utf-8"))["password"]
    assert generated_pw
    # AuthContext repr and public metadata never expose raw secret
    ctx = resolve_auth_context(credentials_file=cred_path, host="192.168.77.1")
    assert generated_pw not in repr(ctx)
    assert generated_pw not in json.dumps(ctx.to_public_metadata())
    assert generated_pw not in json.dumps(prov)

    with (
        patch("verify_e2e.connect_ssh", side_effect=_fake_connect),
        patch("verify_e2e.ssh_run", side_effect=_run_ow),
        patch("verify_e2e.urllib.request.urlopen", return_value=_FakeResp()),
        patch("verify_e2e.audit_default_routes", return_value={"usb_default_route_leak": False}),
        patch("verify_e2e._probe_android", return_value={"reachable": False, "slot_suffix": "UNKNOWN", "active_os": "UNKNOWN"}),
        patch("kit.assert_preflight_ready", return_value={"ready": True}),
    ):
        rc = kit_main([
            "verify",
            "--profile",
            "3-dual-full",
            "--credentials-file",
            str(cred_path),
            "--out",
            str(tmp_path / "verify_out.json"),
        ])
    assert rc == 0
    assert seen_passwords == [(generated_pw,)]
    vrep = json.loads((tmp_path / "verify_out.json").read_text(encoding="utf-8"))
    assert generated_pw not in json.dumps(vrep)
    assert vrep["overall_status"] == "PASS"
    assert vrep["openwrt"]["slot_suffix"] == "_b"
    assert vrep["openwrt"]["slot_evidence_source"] == "/proc/cmdline|bootargs"
    # Active OpenWrt in Profile 3 leaves inactive Android strictly NOT_TESTED (never fake PASS or FAIL)
    assert vrep["checks"]["android_adb"]["status"] == "NOT_TESTED"
    assert vrep["checks"]["android_ufi_services"]["status"] == "NOT_TESTED"

    # 2. Missing cmdline/bootargs must return slot_suffix == "UNKNOWN" and never report wifi_device ('phy0-ap0') as slot
    parsed_no_cmd = _parse_openwrt_boot_evidence(
        "model=f50pro\nboard_id=6\nwifi_device=phy0-ap0\nopenwrt_id=OpenWrt\ncmdline=\nbootargs=\n"
    )
    assert parsed_no_cmd["wifi_device"] == "phy0-ap0"
    assert parsed_no_cmd["slot_suffix"] == "UNKNOWN"
    assert parsed_no_cmd["slot_evidence_source"] == "UNAVAILABLE"

    # 3. Profile 2 marks Android checks NOT_APPLICABLE
    p2_eval = evaluate_e2e_checks(
        profile_id="2-dual-stock-openwrt",
        host_routes={"usb_default_route_leak": False},
        openwrt={"reachable": True, "active_os": "openwrt", "slot_suffix": "_b", "luci_http_status": 200},
        android={"reachable": False},
    )
    assert p2_eval["overall_status"] == "PASS"
    assert p2_eval["checks"]["android_adb"]["status"] == "NOT_APPLICABLE"

    # 4. SSH auth failure -> FAIL and kit verify exits non-zero (1) with redacted secret
    with (
        patch("verify_e2e.connect_ssh", side_effect=RuntimeError(f"Authentication failed for password={generated_pw}")),
        patch("verify_e2e.audit_default_routes", return_value={"usb_default_route_leak": False}),
        patch("verify_e2e._probe_android", return_value={"reachable": False}),
        patch("kit.assert_preflight_ready", return_value={"ready": True}),
    ):
        rc_auth = kit_main([
            "verify",
            "--profile",
            "2-dual-stock-openwrt",
            "--root-password",
            generated_pw,
            "--out",
            str(tmp_path / "verify_auth_fail.json"),
        ])
    assert rc_auth == 1
    auth_rep = json.loads((tmp_path / "verify_auth_fail.json").read_text(encoding="utf-8"))
    assert auth_rep["overall_status"] == "FAIL"
    assert auth_rep["checks"]["openwrt_ssh"]["status"] == "FAIL"
    assert generated_pw not in json.dumps(auth_rep)

    # 5. Android missing su root or missing UFI-TOOLS (:2333/:1146) -> FAIL + non-zero exit
    for bad_android, fail_key in (
        ({"reachable": True, "slot_suffix": "_a", "su_id": "2000", "ports": ":2333 :1146"}, "android_su_root"),
        ({"reachable": True, "slot_suffix": "_a", "su_id": "0", "ports": ":2333"}, "android_ufi_services"),
    ):
        ev_bad = evaluate_e2e_checks(
            profile_id="1-android-ufi",
            host_routes={"usb_default_route_leak": False},
            openwrt={"reachable": False},
            android=bad_android,
        )
        assert ev_bad["overall_status"] == "FAIL"
        assert ev_bad["checks"][fail_key]["status"] == "FAIL"
        assert ev_bad["checks"]["openwrt_ssh"]["status"] == "NOT_APPLICABLE"

    # 6. preflight --strict and assert_preflight_ready fail BEFORE dangerous actions when tools/modules missing
    with patch("kit.resolve_tool", side_effect=FileNotFoundError("no spd_dump")):
        assert kit_main(["preflight", "--strict", "--operation", "flash"]) == 1
        with pytest.raises(RuntimeError, match="Preflight check failed before flash"):
            assert_preflight_ready(operation="flash", tools_dir=tools)
    with patch("kit.importlib.import_module", side_effect=ImportError("no paramiko")):
        assert kit_main(["preflight", "--strict", "--operation", "provision-openwrt"]) == 1


def test_p0_6_offline_plan_dry_run_and_probe_boundaries(
    synthetic_env: dict[str, Path], tmp_path: Path
) -> None:
    """P0-6: Offline plan/auto dry-run NEVER triggers HTTP downloads, REBOOT_DEVICE, BROM spd_dump, SSH/ADB, or NIC mutation."""
    import shutil

    from brom_backup import run_brom_backup
    from fetch_assets import fetch_and_extract
    from kit import main as kit_main

    tools = synthetic_env["tools_dir"]
    backup_src = synthetic_env["backup_dir"]
    adb_pub = synthetic_env["adb_pubkey"]

    with (
        patch("urllib.request.urlopen", side_effect=AssertionError("Forbidden HTTP call in offline mode")),
        patch("brom_backup.trigger_zte_webui_reboot", side_effect=AssertionError("Forbidden WebUI reboot in offline mode")),
        patch("brom_backup.subprocess.Popen", side_effect=AssertionError("Forbidden spd_dump Popen in offline mode")),
        patch("flash_images.subprocess.Popen", side_effect=AssertionError("Forbidden flash Popen in offline mode")),
        patch("provision_openwrt.connect_ssh", side_effect=AssertionError("Forbidden SSH connect in offline mode")),
        patch("provision_android._adb", side_effect=AssertionError("Forbidden ADB call in offline mode")),
        patch("host_network.isolate_usb_rndis_adapter", side_effect=AssertionError("Forbidden NIC mutation in offline mode")),
    ):
        # 1. Default auto without --execute and without backup cleanly reports BACKUP_REQUIRED without touching hardware/network
        work_empty = tmp_path / "auto_no_backup"
        rc_empty = kit_main([
            "auto",
            "--profile",
            "3-dual-full",
            "--work-dir",
            str(work_empty),
            "--tools-dir",
            str(tools),
            "--cache-dir",
            str(tmp_path / "empty_cache"),
        ])
        assert rc_empty == 0
        rep_empty = json.loads((work_empty / "auto_dry_run_report.json").read_text(encoding="utf-8"))
        assert rep_empty["status"] == "BACKUP_REQUIRED"
        assert rep_empty["mode"] == "offline_plan_dry_run"
        assert rep_empty["network_downloads"] == []
        assert rep_empty["device_read_ops"] == []
        assert rep_empty["device_mutations"] == []
        assert rep_empty["device_mutated"] is False
        assert rep_empty["device_rebooted"] is False
        assert rep_empty["host_network_mutated"] is False

        # 2. Offline auto (no --execute) AND kit plan with local backup build complete flash_plan dry-run with zero live/network calls
        work_ready = tmp_path / "auto_with_backup"
        shutil.copytree(backup_src, work_ready / "backup")
        rc_dry = kit_main([
            "auto",
            "--profile",
            "3-dual-full",
            "--work-dir",
            str(work_ready),
            "--tools-dir",
            str(tools),
            "--cache-dir",
            str(tmp_path / "empty_cache"),
            "--adb-pubkey",
            str(adb_pub),
        ])
        assert rc_dry == 0
        rep_dry = json.loads((work_ready / "auto_dry_run_report.json").read_text(encoding="utf-8"))
        assert rep_dry["status"] == "DRY_RUN_READY"
        assert rep_dry["flash"]["dry_run"] is True
        assert rep_dry["flash"]["device_mutated"] is False
        assert rep_dry["network_downloads"] == []
        assert rep_dry["device_read_ops"] == []
        assert rep_dry["device_mutations"] == []
        assert rep_dry["device_rebooted"] is False
        assert rep_dry["host_network_mutated"] is False

        work_plan = tmp_path / "plan_cmd"
        rc_plan = kit_main([
            "plan",
            "--profile",
            "2-dual-stock-openwrt",
            "--work-dir",
            str(work_plan),
            "--backup-dir",
            str(backup_src),
            "--tools-dir",
            str(tools),
        ])
        assert rc_plan == 0
        rep_plan = json.loads((work_plan / "auto_dry_run_report.json").read_text(encoding="utf-8"))
        assert rep_plan["status"] == "DRY_RUN_READY"
        assert rep_plan["device_rebooted"] is False

        # 3. fetch_and_extract(..., offline_only=True) rejects missing archives before HTTP urlopen
        with pytest.raises(FileNotFoundError, match="Offline mode forbids network download"):
            fetch_and_extract(
                host_platform="win64",
                profile="1-android-ufi",
                cache_dir=tmp_path / "no_cache",
                tools_dir=tmp_path / "no_tools",
                local_release_dir=tmp_path / "no_dist",
                offline_only=True,
            )

        # 4. Live BROM backup refuses to enter AutoD / reset device unless authorize_device_reboot=True
        with pytest.raises(PermissionError, match="authorize_device_reboot"):
            run_brom_backup(tmp_path / "blocked_bak", tools_dir=tools)

    # 5. kit.py probe executes read-only online inspection without triggering reboot, flash, or NIC mutation
    ssh_ok = MagicMock()
    ssh_ok.close = MagicMock()

    class _FakeResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    with (
        patch("brom_backup.trigger_zte_webui_reboot", side_effect=AssertionError("Forbidden WebUI reboot in probe")),
        patch("brom_backup.subprocess.Popen", side_effect=AssertionError("Forbidden spd_dump in probe")),
        patch("host_network.isolate_usb_rndis_adapter", side_effect=AssertionError("Forbidden NIC mutation in probe")),
        patch("verify_e2e.connect_ssh", return_value=ssh_ok),
        patch(
            "verify_e2e.ssh_run",
            return_value=(
                0,
                "model=f50pro\nboard_id=6\nwifi_device=phy0-ap0\nopenwrt_id=OpenWrt\ncmdline=androidboot.slot_suffix=_b\nbootargs=\nbutton_long=system-switch\n/dev/root 1 1 1 50% /\n",
                "",
            ),
        ),
        patch("verify_e2e.urllib.request.urlopen", return_value=_FakeResp()),
        patch("verify_e2e.audit_default_routes", return_value={"usb_default_route_leak": False}),
        patch("verify_e2e._probe_android", return_value={"reachable": False, "slot_suffix": "UNKNOWN", "active_os": "UNKNOWN"}),
        patch("kit.assert_preflight_ready", return_value={"ready": True}),
    ):
        probe_out_file = tmp_path / "probe_verify.json"
        rc_probe = kit_main([
            "probe",
            "--profile",
            "2-dual-stock-openwrt",
            "--out",
            str(probe_out_file),
        ])
        assert rc_probe == 0
        probe_json = json.loads(probe_out_file.read_text(encoding="utf-8"))
        assert probe_json["overall_status"] == "PASS"


def test_real_b15_openwrt_cmdline_board_id_and_device_usb_get(tmp_path: Path) -> None:
    """Verify real-hardware OpenWrt sprdboot.slot_suffix, zteboot.zte_boardid, and device-usb get JSON parsing."""
    from provision_openwrt import (
        _apply_usb_net_mode_transition,
        _probe_remote_identity_and_usb_mode,
        resolve_host_usb_net_plan,
    )
    from verify_e2e import _parse_openwrt_boot_evidence

    parsed = _parse_openwrt_boot_evidence(
        "model=f50pro\nboard_id=\nwifi_device=phy0-ap0\nopenwrt_id=OpenWrt\n"
        "cmdline=console=ttyS1 sprdboot.slot_suffix=_b sprdboot.flash=emmc zteboot.zte_boardid=1\n"
        "bootargs=\nbutton_long=system-switch\nusb_mode=rndis\n"
        "/dev/mmcblk0p62 2022600 168392 1837824 8% /mnt/mu300-disk\n"
    )
    assert parsed["board_id"] == "1"
    assert parsed["slot_suffix"] == "_b"
    assert parsed["slot_evidence_source"] == "/proc/cmdline|bootargs"
    assert parsed["active_os"] == "openwrt"
    assert parsed["usb_mode"] == "rndis"

    ssh = MagicMock()
    captured: list[str] = []

    def _fake_ssh(client, cmd, *, check=True, timeout=60.0):
        captured.append(cmd)
        if "usb_get=" in cmd:
            return (
                0,
                'board_id=unknown\ncmdline=console=ttyS1 zteboot.zte_boardid=1\n'
                'usb_get={"ok":1,"net_current":"rndis","net_mode":"rndis"}\n'
                'usb_mode=unknown\nhost_hash=deadbeef1234\n',
                "",
            )
        return 0, "", ""

    with patch("provision_openwrt.ssh_run", side_effect=_fake_ssh):
        ident = _probe_remote_identity_and_usb_mode(ssh)
        assert ident == {"board_id": "1", "usb_mode": "rndis", "host_hash": "deadbeef1234"}

        plan = resolve_host_usb_net_plan(
            host_platform="win64",
            current_mode="ncm",
            requested_mode="rndis",
            persist_mode=False,
        )
        ssh2 = MagicMock()
        with (
            patch("provision_openwrt.wait_for_openwrt_ssh", return_value=ssh2),
            patch("provision_openwrt.time.sleep"),
        ):
            _, trans = _apply_usb_net_mode_transition(
                ssh,
                plan=plan,
                pre_identity={"board_id": "1", "usb_mode": "ncm", "host_hash": "deadbeef1234"},
                openwrt_host="192.168.77.1",
                pw_candidates=("",),
                isolate_host=False,
                target_iface=None,
                usb_topology=None,
                out_dir=tmp_path,
            )
    assert trans["scope"] == "once"
    assert any("device-usb set-net 'rndis' once 1" in c for c in captured)


def test_brom_backup_retries_only_pre_handshake_connection_race(
    synthetic_env: dict[str, Path], tmp_path: Path
) -> None:
    """Verify run_brom_backup retries transient pre-handshake 1782:4d00 'Connection failed' races, never post-handshake."""
    from brom_backup import run_brom_backup

    tools = synthetic_env["tools_dir"]
    fake_exe = tools / "spd_dump_fake.exe"
    fake_exe.write_bytes(b"MZ")

    class _RaceProc(_FakePopen):
        def __init__(self, lines: list[str], rc: int):
            super().__init__(lines)
            self._final_rc = rc

        def wait(self, timeout=None):
            self._rc = self._final_rc
            return self._rc

    # Case 1: attempt 1 hits pre-handshake 'Connection failed'; attempt 2 succeeds cleanly
    p1 = _RaceProc(["Waiting for boot_diag/cali_diag/dl_diag connection (120s)\n", "Connection failed\n"], rc=1)
    p2 = _RaceProc(
        ["Waiting for boot_diag/cali_diag/dl_diag connection (120s)\n", 'BSL_REP_VER: "SPRD4:AutoD\\0"\n', "save dir is ...\n"],
        rc=0,
    )
    out1 = tmp_path / "bak_retry_ok"
    calls = {"n": 0}

    def _spawn1(*a, **k):
        calls["n"] += 1
        return p1 if calls["n"] == 1 else p2

    with (
        patch("brom_backup.build_spd_invocation", return_value=([str(fake_exe)], {"mode": "direct"})),
        patch("brom_backup.subprocess.Popen", side_effect=_spawn1),
        patch("brom_backup.verify_backup_dir", return_value={"checks_passed": True}),
        patch("brom_backup.time.sleep"),
    ):
        res = run_brom_backup(out1, tools_dir=tools, authorize_device_reboot=True)
    assert calls["n"] == 2
    assert res["checks_passed"] is True

    # Case 2: failure AFTER BSL_REP_VER must NEVER retry
    p_post = _RaceProc(
        ["Waiting for boot_diag/cali_diag/dl_diag connection (120s)\n", 'BSL_REP_VER: "SPRD4:AutoD\\0"\n', "Connection failed\n"],
        rc=1,
    )
    out2 = tmp_path / "bak_no_retry_post"
    calls2 = {"n": 0}

    def _spawn2(*a, **k):
        calls2["n"] += 1
        return p_post

    with (
        patch("brom_backup.build_spd_invocation", return_value=([str(fake_exe)], {"mode": "direct"})),
        patch("brom_backup.subprocess.Popen", side_effect=_spawn2),
        patch("brom_backup.time.sleep"),
    ):
        with pytest.raises(RuntimeError, match="spd_dump backup failed rc=1"):
            run_brom_backup(out2, tools_dir=tools, authorize_device_reboot=True)
    assert calls2["n"] == 1


def test_single_session_auto_execute_no_mid_reboot_and_fail_close(
    synthetic_env: dict[str, Path], tmp_path: Path
) -> None:
    """Single-session BROM executes backup -> inspect -> build -> flash -> single reset with zero mid-flow reboot."""
    import shutil

    from kit import main as kit_main

    tools = synthetic_env["tools_dir"]
    fake_exe = tools / "spd_dump_fake.exe"
    fake_exe.write_bytes(b"MZ")
    stock_bak = synthetic_env["backup_dir"]
    good_tbl = list(parse_partition_xml(stock_bak / "partition_list.xml").items())
    work_dir = tmp_path / "single_sess_work"

    class _SingleSessDouble:
        def __init__(self, backup_dir: Path, run_dir: Path):
            self.work_dir = backup_dir
            self.backup_dir = backup_dir
            self.run_dir = run_dir
            self.launch_meta = {"mode": "direct"}
            self.commands: list[list[str]] = []
            self.closed_calls: list[bool] = []
            self.stored: dict[str, bytes] = {}
            for p in stock_bak.iterdir():
                if p.is_file() and p.name not in ("SHA256SUMS.txt", "verification_report.json", "partition_list.xml"):
                    self.stored[p.name] = p.read_bytes()

        def send_line(self, args: list[object]) -> None:
            toks = [str(a) for a in args]
            self.commands.append(toks)
            if len(toks) >= 2 and toks[0] == "r" and toks[1] == "all":
                self.backup_dir.mkdir(parents=True, exist_ok=True)
                for p in stock_bak.iterdir():
                    if p.is_file() and p.name not in ("SHA256SUMS.txt", "verification_report.json", "partition_list.xml"):
                        shutil.copy2(p, self.backup_dir / p.name)
            elif len(toks) >= 2 and toks[0] == "partition_list":
                shutil.copy2(stock_bak / "partition_list.xml", Path(toks[1]))

        def cmd(self, args: list[object], ok: str, errs: tuple[str, ...] = (), timeout: int = 240) -> str:
            toks = [str(a) for a in args]
            self.commands.append(toks)
            if toks[0] == "path":
                Path(toks[1]).mkdir(parents=True, exist_ok=True)
                self.work_dir = Path(toks[1])
            elif toks[0] in ("w", "w_force"):
                self.stored[toks[1]] = Path(toks[2]).read_bytes()
            elif toks[0] == "wof":
                part, off, fpath = toks[1], int(toks[2]), Path(toks[3])
                blob = fpath.read_bytes()
                cur = bytearray(self.stored[part])
                cur[off : off + len(blob)] = blob
                self.stored[part] = bytes(cur)
            return ok

        def switch_dir(self, new_dir: Path) -> None:
            self.cmd(["path", str(new_dir)], "save dir is")

        def table(self, fname: str) -> list[tuple[str, int]]:
            self.commands.append(["partition_list", str(self.work_dir / fname)])
            return good_tbl

        def read_part(self, part: str, size: int, fname: str) -> bytes:
            self.commands.append(["read_part", part, str(size), fname])
            return self.stored[part][:size]

        def safe_unlink(self, fname: str) -> None:
            pass

        def close(self, reboot: bool = True) -> None:
            self.closed_calls.append(reboot)
            if reboot:
                self.commands.append(["reset"])

    sess = _SingleSessDouble(work_dir / "backup", work_dir / "build" / "flash-run")
    open_calls = {"n": 0}

    def _open_once(*a, **k):
        open_calls["n"] += 1
        return sess, {"method": "webui_reboot_device"}

    with (
        patch("kit.assert_preflight_ready", return_value={"ready": True}),
        patch("kit.fetch_and_extract", return_value={"status": "ok", "network_downloads": []}),
        patch("brom_backup.resolve_tool", return_value=fake_exe),
        patch("flash_images.resolve_tool", return_value=fake_exe),
        patch("brom_backup.open_sprd4_session", side_effect=_open_once),
        patch("kit.provision_openwrt", return_value={"status": "OPENWRT_PROVISIONED", "board_id": "6", "host_network": {"usb_default_route_leak": False}}),
        patch(
            "kit.verify_environment",
            return_value={"overall_status": "PASS", "checks": {"host_route_isolation": {"status": "PASS"}}},
        ),
    ):
        rc = kit_main([
            "auto",
            "--profile",
            "2-dual-stock-openwrt",
            "--work-dir",
            str(work_dir),
            "--tools-dir",
            str(tools),
            "--webui-password",
            "testpw",
            "--generate-password",
            "--execute",
        ])

    assert rc == 0
    assert open_calls["n"] == 1  # single BROM session across backup + build + flash!
    assert sess.closed_calls == [True]
    cmd_names = [c[0] for c in sess.commands]
    # Zero resets between r all and wof; single reset at the very end!
    assert cmd_names.count("reset") == 1
    assert cmd_names[-1] == "reset"
    assert cmd_names.index("r") < cmd_names.index("wof") < cmd_names.index("reset")
    report = json.loads((work_dir / "auto_execution_report.json").read_text(encoding="utf-8"))
    assert report["brom_session_mode"] == "single_session_no_mid_reboot"
    assert report["flash"]["reused_brom_session"] is True

    # Failure during build mid-session must close without reset
    work_fail = tmp_path / "single_sess_fail"
    sess_fail = _SingleSessDouble(work_fail / "backup", work_fail / "build" / "flash-run")
    with (
        patch("kit.assert_preflight_ready", return_value={"ready": True}),
        patch("kit.fetch_and_extract", return_value={"status": "ok", "network_downloads": []}),
        patch("brom_backup.resolve_tool", return_value=fake_exe),
        patch("brom_backup.open_sprd4_session", return_value=(sess_fail, None)),
        patch("kit.build_profile", side_effect=RuntimeError("simulated mid-session build error")),
    ):
        with pytest.raises(RuntimeError, match="simulated mid-session build error"):
            kit_main([
                "auto",
                "--profile",
                "2-dual-stock-openwrt",
                "--work-dir",
                str(work_fail),
                "--tools-dir",
                str(tools),
                "--execute",
            ])
    assert sess_fail.closed_calls == [False]
    assert ["reset"] not in sess_fail.commands


def test_multi_transport_reboot_and_delayed_webui_retry(
    synthetic_env: dict[str, Path], tmp_path: Path
) -> None:
    """Wait loop polls WebUI across slow Android boot without dropping retries, falls back to OpenWrt SSH / ADB, and fails fast on WebUI auth rejection."""
    import brom_backup
    import queue as qmod

    tools = synthetic_env["tools_dir"]
    fake_exe = tools / "spd_dump_fake.exe"
    fake_exe.write_bytes(b"MZ")

    class _DelayedBootProc:
        def __init__(self, lines_queue: qmod.Queue[str | None], rc: int = 0):
            self.stdin = io.StringIO()
            self._q = lines_queue
            self.stdout = self._iter_q()
            self._rc = None
            self._final_rc = rc
            self.terminated = False

        def _iter_q(self):
            while True:
                item = self._q.get()
                if item is None:
                    break
                yield item

        def poll(self):
            return self._rc

        def terminate(self):
            self.terminated = True
            self._rc = -15
            self._q.put(None)

        def wait(self, timeout=None):
            if self._rc is None:
                self._rc = self._final_rc
            return self._rc

    # 1. Delayed WebUI boot (2 unreachable probes, succeeds on 3rd) + attempt 1 pre-handshake race -> attempt 2 skips re-triggering WebUI
    q1: qmod.Queue[str | None] = qmod.Queue()
    q1.put("Waiting for boot_diag/cali_diag/dl_diag connection (120s)\n")
    q2: qmod.Queue[str | None] = qmod.Queue()
    q2.put("Waiting for dl_diag connection (120s)\n")
    q2.put('BSL_REP_VER: "SPRD4:AutoD\\0"\n')
    q2.put("save dir is ok\n")
    procs = [_DelayedBootProc(q1, rc=1), _DelayedBootProc(q2, rc=0)]
    spawn_idx = {"i": 0}
    webui_calls = {"n": 0}

    def _spawn_delayed(*a, **k):
        p = procs[spawn_idx["i"]]
        spawn_idx["i"] += 1
        return p

    def _delayed_webui(pw: str, host: str = ""):
        webui_calls["n"] += 1
        if webui_calls["n"] < 3:
            return None
        q1.put("Connection failed\n")
        q1.put(None)
        return {"method": "webui_reboot_device", "cr_version": "B15"}

    clock = {"t": 0.0}

    def _fake_mono() -> float:
        clock["t"] += 1.6
        return clock["t"]

    with (
        patch("brom_backup.build_spd_invocation", return_value=([str(fake_exe)], {"mode": "direct"})),
        patch("brom_backup.subprocess.Popen", side_effect=_spawn_delayed),
        patch("brom_backup._attempt_zte_webui_reboot_once", side_effect=_delayed_webui),
        patch("brom_backup._try_openwrt_ssh_reboot_once", return_value=None),
        patch("brom_backup._try_adb_reboot_once", return_value=None),
        patch("brom_backup.time.monotonic", side_effect=_fake_mono),
        patch("brom_backup.time.sleep"),
    ):
        sess, rb = brom_backup.open_sprd4_session(
            fake_exe,
            tmp_path / "delayed_sess",
            webui_password="pw",
            webui_timeout_sec=60.0,
        )
        sess.close(reboot=False)

    assert spawn_idx["i"] == 2
    assert webui_calls["n"] == 3  # attempt 2 must NOT re-trigger REBOOT_DEVICE
    assert rb == {"method": "webui_reboot_device", "cr_version": "B15"}

    # 2. Wrong WebUI password aborts immediately without retry masking
    q_auth: qmod.Queue[str | None] = qmod.Queue()
    q_auth.put("Waiting for boot_diag/cali_diag/dl_diag connection (120s)\n")
    auth_proc = _DelayedBootProc(q_auth, rc=1)
    with (
        patch("brom_backup.build_spd_invocation", return_value=([str(fake_exe)], {"mode": "direct"})),
        patch("brom_backup.subprocess.Popen", return_value=auth_proc),
        patch("brom_backup._attempt_zte_webui_reboot_once", side_effect=brom_backup.WebUIAuthError("WebUI login failed")),
        patch("brom_backup.time.sleep"),
    ):
        with pytest.raises(brom_backup.WebUIAuthError, match="WebUI login failed"):
            brom_backup.open_sprd4_session(
                fake_exe,
                tmp_path / "auth_fail_sess",
                webui_password="badpw",
            )

    # 3. Fallback priority: WebUI unreachable -> OpenWrt SSH reboot -> ADB reboot
    with (
        patch("brom_backup._attempt_zte_webui_reboot_once", return_value=None),
        patch("brom_backup._try_openwrt_ssh_reboot_once", return_value={"method": "openwrt_ssh_reboot", "host": "192.168.77.1"}),
        patch("brom_backup._try_adb_reboot_once", side_effect=AssertionError("ADB not needed when OpenWrt SSH succeeds")),
    ):
        r_ow = brom_backup.trigger_online_reboot_once(webui_password="pw")
    assert r_ow["method"] == "openwrt_ssh_reboot"

    with (
        patch("brom_backup._attempt_zte_webui_reboot_once", return_value=None),
        patch("brom_backup._try_openwrt_ssh_reboot_once", return_value=None),
        patch("brom_backup._try_adb_reboot_once", return_value={"method": "adb_reboot", "serial": None}),
    ):
        r_adb = brom_backup.trigger_online_reboot_once(tools_dir=tools)
    assert r_adb["method"] == "adb_reboot"
