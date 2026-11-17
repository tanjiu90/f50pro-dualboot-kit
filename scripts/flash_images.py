"""Guarded SPRD4:AutoD (U-Boot autodloader) flasher executing ONLY a SHA-256 verified flash_plan.json.

SPRD4:AutoD operates through functional SPL + U-Boot. All partition writes—especially uboot_b
and BSP sync targets—must pass full SHA-256 readback before misc+2048 slot switching.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

from brom_backup import (
    FATAL_SPD_RE,
    SpdSession,
    _explain_libusb_error,
    open_sprd4_session,
    parse_partition_xml,
    trigger_zte_webui_reboot,
)
from common import (
    DEFAULT_TOOLS_DIR,
    FORBIDDEN_PARTITIONS,
    MISC_BC_OFFSET,
    PROFILE_ALLOWED_BROM_OPS,
    PROFILES,
    REPO_ROOT,
    AuthContext,
    compute_unit_identity_digest,
    read_json,
    resolve_tool,
    sha256_bytes,
    sha256_file,
    write_json,
)


def _token(val: object) -> str:
    s = str(val)
    if any(ch in s for ch in ('\r', '\n', '"')):
        raise ValueError(f"Unsafe spd_dump token: {s!r}")
    return f'"{s}"'


def validate_plan_safety(plan: dict[str, Any]) -> None:
    """Enforce profile allowlists, forbidden partitions, bounds, and artifact digests before hardware access."""
    prof_id = plan["profile"]
    prof = PROFILES[prof_id]
    allowlist = PROFILE_ALLOWED_BROM_OPS[prof_id]

    part_caps: dict[str, int] | None = None
    bdir = plan.get("backup_dir")
    if bdir:
        xml_p = Path(bdir) / "partition_list.xml"
        if xml_p.is_file():
            part_caps = parse_partition_xml(xml_p)

    for op in plan["operations"]:
        part = op["partition"]
        if part in FORBIDDEN_PARTITIONS:
            raise ValueError(f"Forbidden partition in plan: {part}")
        if not prof["touches_slot_a"] and part.endswith("_a"):
            raise ValueError(f"Profile {prof_id} forbids touching slot _a ({part})")
        if part not in allowlist:
            raise ValueError(f"Partition '{part}' is not in profile '{prof_id}' explicit allowlist")
        spec = allowlist[part]
        if op.get("op") != spec["op"]:
            raise ValueError(f"Operation '{op.get('op')}' not permitted for '{part}' (expected '{spec['op']}')")
        offset = int(op.get("offset", 0))
        if offset != spec["offset"]:
            raise ValueError(f"Offset {offset} not permitted for '{part}' (expected {spec['offset']})")

        fpath = Path(op["file"])
        if not fpath.is_file() or sha256_file(fpath) != op["sha256"]:
            raise ValueError(f"Missing or corrupted artifact for {part}: {fpath}")
        actual_sz = fpath.stat().st_size
        declared_sz = int(op.get("size_bytes", actual_sz))
        if declared_sz <= 0 or actual_sz != declared_sz:
            raise ValueError(f"Size mismatch for {part}: file={actual_sz} declared={declared_sz}")
        if spec.get("exact_size") is not None and declared_sz != spec["exact_size"]:
            raise ValueError(f"Partition '{part}' requires exact length {spec['exact_size']} B, got {declared_sz}")
        if part_caps is not None and part in part_caps and part_caps[part] > 0:
            if offset + declared_sz > part_caps[part]:
                raise ValueError(
                    f"Write for '{part}' ({offset}+{declared_sz} B) exceeds GPT capacity ({part_caps[part]} B)"
                )

    if bdir and not plan.get("device_identity"):
        raise ValueError("Flash plan missing mandatory device_identity target binding")


class _SpdSession(SpdSession):
    """Subclass preserving flash_images.subprocess.Popen patchability while sharing SpdSession."""

    def __init__(
        self,
        spd_dump: Path,
        work_dir: Path,
        wait_sec: int = 120,
        *,
        tools_dir: Path = DEFAULT_TOOLS_DIR,
        spd_mode: str = "auto",
        usb_dev: str | None = None,
        cwd: Path | None = None,
        log_name: str = "spd_dump_flash.log",
        log_path: Path | None = None,
        log_mode: str = "w",
    ):
        super().__init__(
            spd_dump,
            work_dir,
            wait_sec=wait_sec,
            tools_dir=tools_dir,
            spd_mode=spd_mode,
            usb_dev=usb_dev,
            cwd=cwd,
            log_name=log_name,
            log_path=log_path,
            log_mode=log_mode,
            popen_factory=subprocess.Popen,
        )


def _probe_failure_diag(sess: Any, exc: Exception) -> dict[str, Any]:
    """Attempt read-only partition_list diagnostic on failure without sending reset or writes."""
    err_txt = str(exc)
    transport_lost = bool(
        FATAL_SPD_RE.search(err_txt)
        or isinstance(exc, TimeoutError)
        or "exited early" in err_txt.lower()
    )
    info: dict[str, Any] = {
        "probed": False,
        "responsive": False,
        "transport_lost": transport_lost,
        "note": (
            "Closed session without sending reset; whether target stays in autodloader depends on "
            "USB link and on-device timeout and cannot be guaranteed permanently."
        ),
    }
    if transport_lost:
        info["skip_reason"] = "USB/transport error or timeout detected; skipped extra diagnostic probe"
        return info
    try:
        tbl = sess.table("failure_diag.xml")
        info["probed"] = True
        info["responsive"] = bool(tbl)
        info["partition_count"] = len(tbl)
    except Exception as probe_exc:
        info["probed"] = True
        info["responsive"] = False
        info["probe_error"] = str(probe_exc)
    return info


def _verify_live_target_identity(
    sess: Any,
    plan: dict[str, Any],
    *,
    confirm_weak_identity: bool = False,
    live_board_id: str | None = None,
    live_usb_topology: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify connected device matches plan device_identity without writing raw PII/NV to logs."""
    identity = plan.get("device_identity")
    if not identity or not isinstance(identity, dict):
        raise RuntimeError("Flash plan missing target device_identity binding; re-run `kit.py build`")

    unit_specs = identity.get("unit_identity_partitions") or {}
    if identity.get("identity_strength") != "strong" or not unit_specs or not identity.get("unit_identity_sha256"):
        if not confirm_weak_identity:
            raise RuntimeError(
                "Target device identity is weak/insufficient (missing non-zero per-unit calibration/identity digest). "
                "Automatic flash refused; verify physical target manually and pass explicit confirmation if intentional."
            )
    if live_board_id and identity.get("board_id") and str(live_board_id) != str(identity["board_id"]):
        raise RuntimeError(f"Target board_id mismatch: plan={identity['board_id']} vs live={live_board_id}")
    if live_usb_topology and identity.get("usb_topology"):
        for k in ("bus", "port_path", "serial"):
            pv = identity["usb_topology"].get(k)
            lv = live_usb_topology.get(k)
            if pv and lv and str(pv) != str(lv):
                raise RuntimeError(f"Target USB topology mismatch ({k}): plan={pv} vs live={lv}")

    live_part_records: dict[str, dict[str, Any]] = {}
    for pname, spec in sorted(unit_specs.items()):
        sz = int(spec["size_bytes"])
        probe_name = f"_{pname}_id_probe.bin"
        raw = sess.read_part(pname, sz, probe_name)
        sess.safe_unlink(probe_name)
        digest = sha256_bytes(raw)
        if not raw or not any(raw):
            raise RuntimeError(f"Live identity partition '{pname}' unexpectedly all-zero on target")
        if digest != spec["sha256"]:
            raise RuntimeError(
                f"Target device identity mismatch on read-only '{pname}': connected hardware is NOT the backup source device"
            )
        live_part_records[pname] = {"size_bytes": len(raw), "sha256": digest}

    if unit_specs:
        live_unit = compute_unit_identity_digest(live_part_records)
        if live_unit["unit_identity_sha256"] != identity["unit_identity_sha256"]:
            raise RuntimeError("Target unit_identity_sha256 mismatch against bound flash plan")

    # Cross-check immutable stock firmware partition (vendor_boot_a is untouched across all 3 profiles)
    fw = identity.get("firmware_build") or {}
    expected_vb_sha = fw.get("vendor_boot_a_sha256")
    if expected_vb_sha:
        vb_sz = (Path(plan["backup_dir"]) / "vendor_boot_a").stat().st_size
        vb_raw = sess.read_part("vendor_boot_a", vb_sz, "_vendor_boot_a_id_probe.bin")
        sess.safe_unlink("_vendor_boot_a_id_probe.bin")
        if sha256_bytes(vb_raw) != expected_vb_sha:
            raise RuntimeError("Target vendor_boot_a firmware build digest mismatch against backup/plan")

    return {
        "verified": True,
        "identity_strength": identity.get("identity_strength"),
        "verified_sources": sorted(live_part_records.keys()),
        "unit_identity_sha256": identity.get("unit_identity_sha256"),
    }


def execute_flash(
    plan_path: Path,
    *,
    tools_dir: Path = DEFAULT_TOOLS_DIR,
    webui_password: str | None = None,
    webui_host: str = "http://192.168.0.1:8080",
    openwrt_host: str = "192.168.77.1",
    auth_context: AuthContext | None = None,
    adb_serial: str | None = None,
    execute: bool = False,
    spd_mode: str = "auto",
    usb_dev: str | None = None,
    confirm_weak_identity: bool = False,
    board_id: str | None = None,
    usb_topology: dict[str, Any] | None = None,
    active_session: SpdSession | None = None,
) -> dict[str, Any]:
    """Execute or dry-run a verified flash_plan.json with full readback verification and safe failure handling."""
    plan = read_json(plan_path)
    validate_plan_safety(plan)
    if not execute:
        return {
            "dry_run": True,
            "device_mutated": False,
            "device_rebooted": False,
            "profile": plan["profile"],
            "spd_mode": spd_mode,
            "operations": [
                {"op": o["op"], "partition": o["partition"], "size_bytes": o["size_bytes"]}
                for o in plan["operations"]
            ],
        }

    backup_dir = Path(plan["backup_dir"])
    run_dir = Path(plan["out_dir"]) / "flash-run"
    run_dir.mkdir(parents=True, exist_ok=True)
    prefer_var = "termux-usb" if spd_mode == "termux-usb" else ("su" if spd_mode == "su" else None)
    spd_dump = resolve_tool("spd_dump", tools_dir, prefer_variant=prefer_var)
    expected_xml = parse_partition_xml(backup_dir / "partition_list.xml")

    sess: Any = active_session
    reused_session = active_session is not None
    if sess is not None:
        if getattr(sess, "work_dir", None) != run_dir and hasattr(sess, "switch_dir"):
            sess.switch_dir(run_dir)
    else:
        try:
            sess, _ = open_sprd4_session(
                spd_dump,
                run_dir,
                wait_sec=90,
                tools_dir=tools_dir,
                spd_mode=spd_mode,
                usb_dev=usb_dev,
                webui_password=webui_password,
                webui_host=webui_host,
                openwrt_host=openwrt_host,
                auth_context=auth_context,
                adb_serial=adb_serial,
                webui_timeout_sec=90.0,
                session_cls=_SpdSession,
                webui_trigger_fn=trigger_zte_webui_reboot,
            )
        except Exception as exc:
            fail_state = {
                "status": "FLASH_FAILED",
                "profile": plan["profile"],
                "failed_stage": "connect_sprd4",
                "error": str(exc) or "Failed to connect to F50 Pro SPRD4/BROM port",
                "reset_sent": False,
                "slot_switched": False,
                "auto_rollback_attempted": False,
                "verified_partitions": [],
                "pending_operations": [
                    {"op": o["op"], "partition": o["partition"], "offset": o.get("offset", 0), "size_bytes": o["size_bytes"]}
                    for o in plan["operations"]
                ],
                "log_path": str(run_dir / "spd_dump_flash.log"),
            }
            write_json(run_dir / "flash_state.json", fail_state)
            raise RuntimeError(fail_state["error"]) from exc

    w_ops = [o for o in plan["operations"] if o["op"] in ("w", "w_force")]
    w_ops.sort(key=lambda o: (o["partition"] == "init_boot_b", o["partition"] == "fulldumpdb"))
    wof_ops = [o for o in plan["operations"] if o["op"] == "wof"]
    ordered_ops = [*w_ops, *wof_ops]

    results: dict[str, Any] = {}
    verified_partitions: list[dict[str, Any]] = []
    completed_keys: set[tuple[str, str, int]] = set()
    failed_stage = "precheck_gpt"

    def _op_key(o: dict[str, Any]) -> tuple[str, str, int]:
        return (o["op"], o["partition"], int(o.get("offset", 0)))

    try:
        before_tbl = sess.table("before.xml")
        if dict(before_tbl) != expected_xml:
            raise RuntimeError("Live GPT partition table differs from verified backup")

        failed_stage = "precheck_identity"
        identity_check = _verify_live_target_identity(
            sess,
            plan,
            confirm_weak_identity=confirm_weak_identity,
            live_board_id=board_id,
            live_usb_topology=usb_topology,
        )

        # Write full partitions first (fulldumpdb before init_boot_b, init_boot_b uses w_force + guard)
        for op in w_ops:
            part = op["partition"]
            fpath = Path(op["file"])
            sz = op["size_bytes"]
            exp_sha = op["sha256"]

            failed_stage = f"pre_read:{part}"
            existing = sess.read_part(part, sz, f"{part}_pre.bin")
            sess.safe_unlink(f"{part}_pre.bin")
            if sha256_bytes(existing) == exp_sha:
                rec = {"partition": part, "method": "already_verified", "size_bytes": sz, "sha256": exp_sha}
                results[part] = {"method": "already_verified", "sha256": exp_sha}
                verified_partitions.append(rec)
                completed_keys.add(_op_key(op))
                continue

            failed_stage = f"write:{part}"
            if op["op"] == "w_force":
                sess.cmd(["w_force", part, str(fpath)], f"Force Write {part} Done", timeout=300)
                failed_stage = f"gpt_recheck_after_force:{part}"
                if sess.table("after_force.xml") != before_tbl:
                    raise RuntimeError("Partition table altered after w_force")
            else:
                sess.cmd(
                    ["w", part, str(fpath)],
                    f"Write Part Done: {part},",
                    errs=("BSL_REP_", "incompatible", "failed", "Failed"),
                    timeout=300,
                )

            failed_stage = f"readback:{part}"
            rb = sess.read_part(part, sz, f"{part}_rb.bin")
            sess.safe_unlink(f"{part}_rb.bin")
            rb_sha = sha256_bytes(rb)
            if rb_sha != exp_sha:
                raise RuntimeError(f"Readback SHA mismatch on {part}: {rb_sha} != {exp_sha}")
            rec = {"partition": part, "method": op["op"], "size_bytes": sz, "readback_sha256": rb_sha}
            results[part] = {"method": op["op"], "size_bytes": sz, "readback_sha256": rb_sha}
            verified_partitions.append(rec)
            completed_keys.add(_op_key(op))

        # Offset writes (e.g. misc+2048 BCAB trial block) written LAST after all partitions verify
        for op in wof_ops:
            part = op["partition"]
            offset = op["offset"]
            sz = op["size_bytes"]
            data = Path(op["file"]).read_bytes()
            failed_stage = f"offset_pre_read:{part}+{offset}"
            before_full = sess.read_part(part, (backup_dir / part).stat().st_size, f"{part}_before.bin")
            failed_stage = f"offset_write:{part}+{offset}"
            sess.cmd(["wof", part, offset, op["file"]], "w_mem_to_part_offset: wrote to", timeout=60)
            failed_stage = f"offset_readback:{part}+{offset}"
            after_full = sess.read_part(part, len(before_full), f"{part}_after.bin")
            if after_full != before_full[:offset] + data + before_full[offset + sz :]:
                raise RuntimeError(f"Offset write safety check failed on {part}+{offset}")
            rec = {"partition": f"{part}+{offset}", "method": "wof", "size_bytes": sz, "sha256": sha256_bytes(data)}
            results[f"{part}+{offset}"] = {"method": "wof", "sha256": sha256_bytes(data)}
            verified_partitions.append(rec)
            completed_keys.add(_op_key(op))

        # Explicit success path: only reset after every operation + readback verified
        failed_stage = "completed"
        summary = {
            "status": "FLASH_AND_READBACK_VERIFIED",
            "profile": plan["profile"],
            "reused_brom_session": reused_session,
            "device_identity_verified": identity_check,
            "reset_sent": True,
            "slot_switched": bool(wof_ops),
            "auto_rollback_attempted": False,
            "verified_partitions": verified_partitions,
            "pending_operations": [],
            "results": results,
            "log_path": str(run_dir / ("spd_dump_session.log" if reused_session else "spd_dump_flash.log")),
        }
        write_json(run_dir / "flash_state.json", summary)
        write_json(run_dir / "flash_result.json", summary)
        sess.close(reboot=True)
        return summary
    except Exception as exc:
        diag = _probe_failure_diag(sess, exc)
        sess.close(reboot=False)
        pending = [
            {
                "op": o["op"],
                "partition": o["partition"],
                "offset": o.get("offset", 0),
                "size_bytes": o["size_bytes"],
            }
            for o in ordered_ops
            if _op_key(o) not in completed_keys
        ]
        fail_state = {
            "status": "FLASH_FAILED",
            "profile": plan["profile"],
            "failed_stage": failed_stage,
            "error": str(exc),
            "reset_sent": False,
            "slot_switched": False,
            "auto_rollback_attempted": False,
            "verified_partitions": verified_partitions,
            "pending_operations": pending,
            "diagnostic_channel": diag,
            "log_path": str(run_dir / "spd_dump_flash.log"),
        }
        write_json(run_dir / "flash_state.json", fail_state)
        write_json(run_dir / "flash_failure_report.json", fail_state)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    parser.add_argument("--webui-password")
    parser.add_argument("--webui-host", default="http://192.168.0.1:8080")
    parser.add_argument("--openwrt-host", default="192.168.77.1")
    parser.add_argument("--adb-serial")
    parser.add_argument("--spd-mode", default="auto", choices=["auto", "direct", "sudo", "su", "termux-usb"])
    parser.add_argument("--usb-dev", help="Explicit Termux OTG /dev/bus/usb/XXX/YYY path for --spd-mode termux-usb")
    parser.add_argument("--confirm-weak-identity", action="store_true", help="Explicit manual override only if unit identity partitions are absent/all-zero")
    parser.add_argument("--board-id", help="Expected target board_id (1 or 6)")
    parser.add_argument("--execute", action="store_true", help="Actually flash device (default is dry-run)")
    args = parser.parse_args()
    p = args.plan if args.plan.is_absolute() else (REPO_ROOT / args.plan)
    res = execute_flash(
        p,
        tools_dir=args.tools_dir,
        webui_password=args.webui_password,
        webui_host=args.webui_host,
        openwrt_host=args.openwrt_host,
        adb_serial=args.adb_serial,
        execute=args.execute,
        spd_mode=args.spd_mode,
        usb_dev=args.usb_dev,
        confirm_weak_identity=args.confirm_weak_identity,
        board_id=args.board_id,
    )
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
