"""Safety guardrail, forbidden-partition, dry-run, and CLI dispatch tests."""
from __future__ import annotations

import pytest
from pathlib import Path

from build_images import _op, build_profile
from common import FORBIDDEN_PARTITIONS, write_json
from flash_images import execute_flash, validate_plan_safety
from kit import main as kit_main


@pytest.mark.parametrize("part", sorted(FORBIDDEN_PARTITIONS))
def test_forbidden_partitions_rejected_everywhere(tmp_path: Path, part: str) -> None:
    """Ensure every protected calibration/NV/super/userdata partition triggers hard rejection."""
    dummy = tmp_path / "dummy.bin"
    dummy.write_bytes(b"1234")
    with pytest.raises(ValueError, match="forbidden partition"):
        _op(part, dummy)

    bad_plan = {
        "profile": "3-dual-full",
        "operations": [{"op": "w", "partition": part, "file": str(dummy), "sha256": "0" * 64}],
    }
    with pytest.raises(ValueError, match="Forbidden partition"):
        validate_plan_safety(bad_plan)


def test_profile_2_forbids_slot_a_mutations(tmp_path: Path) -> None:
    """Profile 2 must fail hard if a tampered plan tries touching any _a partition."""
    dummy = tmp_path / "init_boot_a.img"
    dummy.write_bytes(b"ABCD")
    tampered = {
        "profile": "2-dual-stock-openwrt",
        "operations": [{"op": "w", "partition": "init_boot_a", "file": str(dummy), "sha256": "0" * 64}],
    }
    with pytest.raises(ValueError, match="forbids touching slot _a"):
        validate_plan_safety(tampered)


def test_corrupted_artifact_sha_fails_dry_run(synthetic_env: dict[str, Path]) -> None:
    """Verify execute_flash checks SHA-256 even in dry-run before touching hardware."""
    out_dir = synthetic_env["out_dir"] / "p1_tamper"
    plan = build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="1-android-ufi",
        out_dir=out_dir,
        tools_dir=synthetic_env["tools_dir"],
        adb_pubkey_path=synthetic_env["adb_pubkey"],
    )
    dry = execute_flash(out_dir / "flash_plan.json", execute=False)
    assert dry["dry_run"] is True
    assert dry["device_mutated"] is False

    plan["operations"][0]["sha256"] = "0" * 64
    write_json(out_dir / "flash_plan.json", plan)
    with pytest.raises(ValueError, match="Missing or corrupted"):
        execute_flash(out_dir / "flash_plan.json", execute=False)


def test_kit_cli_preflight_and_dry_run(synthetic_env: dict[str, Path], capsys: pytest.CaptureFixture[str]) -> None:
    """Exercise kit.py preflight, backup --verify-only, build, and flash dry-run CLI commands."""
    assert kit_main(["preflight"]) == 0
    assert kit_main(["backup", "--output-dir", str(synthetic_env["backup_dir"]), "--verify-only"]) == 0
    out_dir = synthetic_env["out_dir"] / "cli_p2"
    assert kit_main([
        "build",
        "--backup-dir",
        str(synthetic_env["backup_dir"]),
        "--profile",
        "2-dual-stock-openwrt",
        "--out-dir",
        str(out_dir),
        "--tools-dir",
        str(synthetic_env["tools_dir"]),
    ]) == 0
    capsys.readouterr()
    assert kit_main(["flash", "--plan", str(out_dir / "flash_plan.json")]) == 0
    stdout = capsys.readouterr().out
    assert '"dry_run": true' in stdout
    assert '"device_mutated": false' in stdout
