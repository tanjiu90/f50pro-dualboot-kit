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

    # Device B has identical GPT & identical boot/vendor_boot/trustos firmware, only prodnv/miscdata differ!
    mib = 1 << 20
    dev_b_prodnv = (b"SYNTH_UNIT_B_PRODNV!" * ((mib // 20) + 1))[:mib]
    dev_b_miscdata = (b"SYNTH_UNIT_B_MISC!" * ((mib // 18) + 1))[:mib]

    def _read_device_b(part: str, sz: int, fname: str) -> bytes:
        if part == "prodnv":
            return dev_b_prodnv[:sz]
        if part == "miscdata":
            return dev_b_miscdata[:sz]
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
    assert "SYNTH_UNIT_A_PRODNV" not in plan_txt and "SYNTH_UNIT_A_MISC" not in plan_txt
    assert "SYNTH_UNIT_A_PRODNV" not in facts_txt and "SYNTH_UNIT_A_MISC" not in facts_txt

    # Weak identity (all-zero prodnv/miscdata) must refuse automatic flash without confirm_weak_identity
    mib = 1 << 20
    (dev_a_backup / "prodnv").write_bytes(b"\x00" * mib)
    (dev_a_backup / "miscdata").write_bytes(b"\x00" * mib)
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
