"""Guarded SPRD4:AutoD (U-Boot autodloader) flasher executing ONLY a SHA-256 verified flash_plan.json.

SPRD4:AutoD operates through functional SPL + U-Boot. All partition writes—especially uboot_b
and BSP sync targets—must pass full SHA-256 readback before misc+2048 slot switching.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import re
import subprocess
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from brom_backup import (
    FATAL_SPD_RE,
    _explain_libusb_error,
    build_spd_invocation,
    parse_partition_xml,
    trigger_zte_webui_reboot,
)
from common import (
    DEFAULT_TOOLS_DIR,
    FORBIDDEN_PARTITIONS,
    MISC_BC_OFFSET,
    PROFILES,
    REPO_ROOT,
    detect_host_platform,
    read_json,
    resolve_tool,
    sha256_bytes,
    sha256_file,
    win_no_window_kwargs,
    write_json,
)


def _token(val: object) -> str:
    s = str(val)
    if any(ch in s for ch in ('\r', '\n', '"')):
        raise ValueError(f"Unsafe spd_dump token: {s!r}")
    return f'"{s}"'


def validate_plan_safety(plan: dict[str, Any]) -> None:
    """Enforce profile boundaries, forbidden partitions, and artifact digests before touching hardware."""
    prof = PROFILES[plan["profile"]]
    for op in plan["operations"]:
        part = op["partition"]
        if part in FORBIDDEN_PARTITIONS:
            raise ValueError(f"Forbidden partition in plan: {part}")
        if not prof["touches_slot_a"] and part.endswith("_a"):
            raise ValueError(f"Profile {plan['profile']} forbids touching slot _a ({part})")
        fpath = Path(op["file"])
        if not fpath.is_file() or sha256_file(fpath) != op["sha256"]:
            raise ValueError(f"Missing or corrupted artifact for {part}: {fpath}")


class _SpdSession:
    def __init__(
        self,
        spd_dump: Path,
        work_dir: Path,
        wait_sec: int = 120,
        *,
        tools_dir: Path = DEFAULT_TOOLS_DIR,
        spd_mode: str = "auto",
        usb_dev: str | None = None,
    ):
        self.work_dir = work_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.lines: queue.Queue[str | None] = queue.Queue()
        spd_args = [
            "--wait",
            str(wait_sec),
            "--kickto",
            "2",
            "--verbose",
            "1",
            "g_w_force",
            "0",
            "path",
            str(work_dir),
        ]
        if spd_mode in ("auto", "direct"):
            plat = detect_host_platform()
            if plat == "android-arm64" and (not hasattr(os, "geteuid") or os.geteuid() != 0):
                cmd, self.launch_meta = build_spd_invocation(tools_dir, spd_args, spd_mode=spd_mode, usb_dev=usb_dev)
            else:
                cmd = [str(spd_dump), *spd_args]
                self.launch_meta = {"platform": plat, "mode": "direct", "binary": str(spd_dump)}
        else:
            cmd, self.launch_meta = build_spd_invocation(tools_dir, spd_args, spd_mode=spd_mode, usb_dev=usb_dev)

        self.proc = subprocess.Popen(
            cmd,
            cwd=work_dir,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            **win_no_window_kwargs(),
        )
        self.log = (work_dir / "spd_dump_flash.log").open("w", encoding="utf-8")
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self) -> None:
        assert self.proc.stdout
        for line in self.proc.stdout:
            self.log.write(line)
            self.log.flush()
            self.lines.put(line)
        self.lines.put(None)

    def expect_any(self, markers: tuple[str, ...], timeout: int = 240) -> tuple[str, list[str]]:
        deadline = time.monotonic() + timeout
        buf: list[str] = []
        while time.monotonic() < deadline:
            try:
                line = self.lines.get(timeout=min(1.0, max(0.05, deadline - time.monotonic())))
            except queue.Empty:
                continue
            if line is None:
                raise RuntimeError(f"spd_dump exited early; tail={buf[-8:]}")
            buf.append(line.strip())
            if FATAL_SPD_RE.search(line) and "Waiting" not in line:
                meta = getattr(self, "launch_meta", {})
                raise RuntimeError(f"Fatal spd_dump output: {_explain_libusb_error(line.strip(), meta)}")
            for m in markers:
                if m in line:
                    return m, buf
        raise TimeoutError(f"Timed out waiting for {markers}; tail={buf[-8:]}")

    def cmd(self, args: list[object], ok: str, errs: tuple[str, ...] = (), timeout: int = 240) -> str:
        assert self.proc.stdin
        self.proc.stdin.write(" ".join(_token(a) for a in args) + "\n")
        self.proc.stdin.flush()
        hit, _ = self.expect_any((ok, *errs), timeout=timeout)
        if hit != ok:
            raise RuntimeError(f"Command {args[0]} hit error marker: {hit}")
        return hit

    def read_part(self, part: str, size: int, fname: str) -> bytes:
        p = self.work_dir / fname
        p.unlink(missing_ok=True)
        self.cmd(["read_part", part, "0", size, fname], f"Read Part Done: {part}+", timeout=300)
        self.expect_any(("recv: type = 0x80",), timeout=30)
        deadline = time.monotonic() + 10.0
        while True:
            try:
                data = p.read_bytes()
                if len(data) == size:
                    return data
            except PermissionError:
                pass
            if time.monotonic() > deadline:
                raise RuntimeError(f"Readback incomplete for {part} ({size} B)")
            time.sleep(0.05)

    def safe_unlink(self, fname: str) -> None:
        p = self.work_dir / fname
        for _ in range(40):
            try:
                p.unlink(missing_ok=True)
                return
            except PermissionError:
                time.sleep(0.05)

    def table(self, fname: str) -> list[tuple[str, int]]:
        p = self.work_dir / fname
        self.cmd(["partition_list", str(p)], "userdata", timeout=60)
        return list(parse_partition_xml(p).items())

    def close(self, reboot: bool = True) -> None:
        if self.proc.poll() is None:
            if reboot and self.proc.stdin:
                try:
                    self.proc.stdin.write('"reset"\n')
                    self.proc.stdin.flush()
                except OSError:
                    pass
                try:
                    self.proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self.proc.terminate()
            else:
                self.proc.terminate()
            self.proc.wait(timeout=15)
        self.log.close()


def execute_flash(
    plan_path: Path,
    *,
    tools_dir: Path = DEFAULT_TOOLS_DIR,
    webui_password: str | None = None,
    webui_host: str = "http://192.168.0.1:8080",
    execute: bool = False,
    spd_mode: str = "auto",
    usb_dev: str | None = None,
) -> dict[str, Any]:
    """Execute or dry-run a verified flash_plan.json with full readback verification."""
    plan = read_json(plan_path)
    validate_plan_safety(plan)
    if not execute:
        return {
            "dry_run": True,
            "device_mutated": False,
            "profile": plan["profile"],
            "spd_mode": spd_mode,
            "operations": [
                {"op": o["op"], "partition": o["partition"], "size_bytes": o["size_bytes"]}
                for o in plan["operations"]
            ],
        }

    backup_dir = Path(plan["backup_dir"])
    run_dir = Path(plan["out_dir"]) / "flash-run"
    prefer_var = "termux-usb" if spd_mode == "termux-usb" else ("su" if spd_mode == "su" else None)
    spd_dump = resolve_tool("spd_dump", tools_dir, prefer_variant=prefer_var)
    expected_xml = parse_partition_xml(backup_dir / "partition_list.xml")

    sess: _SpdSession | None = None
    for attempt in range(1, 5):
        cand = _SpdSession(
            spd_dump,
            run_dir,
            wait_sec=90,
            tools_dir=tools_dir,
            spd_mode=spd_mode,
            usb_dev=usb_dev,
        )
        try:
            first_res = cand.expect_any(
                ("Waiting for boot_diag", "Waiting for dl_diag", "Try to convert termux transfered usb port fd."),
                timeout=20,
            )
            hit = first_res[0] if isinstance(first_res, tuple) and first_res else str(first_res)
            if attempt == 1 and webui_password and "Waiting for boot_diag" in hit:
                time.sleep(0.8)
                trigger_zte_webui_reboot(webui_password, host=webui_host)
            cand.expect_any(("save dir is",), timeout=100)
            sess = cand
            break
        except Exception:
            cand.close(reboot=False)
            time.sleep(0.4)
    if sess is None:
        raise RuntimeError("Failed to connect to F50 Pro SPRD4/BROM port")

    results: dict[str, Any] = {}
    try:
        before_tbl = sess.table("before.xml")
        if dict(before_tbl) != expected_xml:
            raise RuntimeError("Live GPT partition table differs from verified backup")

        # Write full partitions first (fulldumpdb before init_boot_b, init_boot_b uses w_force + guard)
        w_ops = [o for o in plan["operations"] if o["op"] in ("w", "w_force")]
        w_ops.sort(key=lambda o: (o["partition"] == "init_boot_b", o["partition"] == "fulldumpdb"))

        for op in w_ops:
            part = op["partition"]
            fpath = Path(op["file"])
            sz = op["size_bytes"]
            exp_sha = op["sha256"]

            existing = sess.read_part(part, sz, f"{part}_pre.bin")
            sess.safe_unlink(f"{part}_pre.bin")
            if sha256_bytes(existing) == exp_sha:
                results[part] = {"method": "already_verified", "sha256": exp_sha}
                continue

            if op["op"] == "w_force":
                sess.cmd(["w_force", part, str(fpath)], f"Force Write {part} Done", timeout=300)
                if sess.table("after_force.xml") != before_tbl:
                    raise RuntimeError("Partition table altered after w_force")
            else:
                sess.cmd(
                    ["w", part, str(fpath)],
                    f"Write Part Done: {part},",
                    errs=("BSL_REP_", "incompatible", "failed", "Failed"),
                    timeout=300,
                )

            rb = sess.read_part(part, sz, f"{part}_rb.bin")
            sess.safe_unlink(f"{part}_rb.bin")
            rb_sha = sha256_bytes(rb)
            if rb_sha != exp_sha:
                raise RuntimeError(f"Readback SHA mismatch on {part}: {rb_sha} != {exp_sha}")
            results[part] = {"method": op["op"], "size_bytes": sz, "readback_sha256": rb_sha}

        # Offset writes (e.g. misc+2048 BCAB trial block) written LAST after all partitions verify
        for op in [o for o in plan["operations"] if o["op"] == "wof"]:
            part = op["partition"]
            offset = op["offset"]
            sz = op["size_bytes"]
            data = Path(op["file"]).read_bytes()
            before_full = sess.read_part(part, (backup_dir / part).stat().st_size, f"{part}_before.bin")
            sess.cmd(["wof", part, offset, op["file"]], "w_mem_to_part_offset: wrote to", timeout=60)
            after_full = sess.read_part(part, len(before_full), f"{part}_after.bin")
            if after_full != before_full[:offset] + data + before_full[offset + sz :]:
                raise RuntimeError(f"Offset write safety check failed on {part}+{offset}")
            results[f"{part}+{offset}"] = {"method": "wof", "sha256": sha256_bytes(data)}

        summary = {"status": "FLASH_AND_READBACK_VERIFIED", "profile": plan["profile"], "results": results}
        write_json(run_dir / "flash_result.json", summary)
        sess.close(reboot=True)
        return summary
    except Exception:
        sess.close(reboot=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    parser.add_argument("--webui-password")
    parser.add_argument("--webui-host", default="http://192.168.0.1:8080")
    parser.add_argument("--spd-mode", default="auto", choices=["auto", "direct", "sudo", "su", "termux-usb"])
    parser.add_argument("--usb-dev", help="Explicit Termux OTG /dev/bus/usb/XXX/YYY path for --spd-mode termux-usb")
    parser.add_argument("--execute", action="store_true", help="Actually flash device (default is dry-run)")
    args = parser.parse_args()
    p = args.plan if args.plan.is_absolute() else (REPO_ROOT / args.plan)
    res = execute_flash(
        p,
        tools_dir=args.tools_dir,
        webui_password=args.webui_password,
        webui_host=args.webui_host,
        execute=args.execute,
        spd_mode=args.spd_mode,
        usb_dev=args.usb_dev,
    )
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
