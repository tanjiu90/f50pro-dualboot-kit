"""Read-only Spreadtrum/Unisoc SPRD4:AutoD (U-Boot autodloader) partition dumper and verifier.

Note: SPRD4:AutoD requires functional on-device SPL + U-Boot. Bare-metal SPRD3 BootROM
recovery when U-Boot fails to load requires external signed UMS9632 FDL1/FDL2 not bundled here.
"""
from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
import os
import queue
import re
import shlex
import shutil
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from common import (
    DEFAULT_TOOLS_DIR,
    REPO_ROOT,
    detect_host_platform,
    parse_boot_control,
    resolve_tool,
    sha256_file,
    win_no_window_kwargs,
    write_json,
)

FATAL_SPD_RE = re.compile(
    r"LIBUSB_ERROR_(?:PIPE|NO_DEVICE|IO|ACCESS)|find port failed|timeout reached|need provide --usb-fd|not a spd device",
    re.I,
)

CORE_PARTITIONS = frozenset({
    "prodnv",
    "calinv",
    "misc",
    "trustos_a",
    "trustos_b",
    "sml_a",
    "sml_b",
    "uboot_a",
    "uboot_b",
    "teecfg_a",
    "teecfg_b",
    "dtbo_a",
    "dtbo_b",
    "boot_a",
    "boot_b",
    "vendor_boot_a",
    "vendor_boot_b",
    "init_boot_a",
    "init_boot_b",
    "vbmeta_a",
    "vbmeta_system_a",
    "vbmeta_vendor_a",
    "super",
    "fulldumpdb",
})

CHSIZE_OR_TRIM_PARTITIONS = frozenset({
    "splloader",
    "sml_a",
    "sml_b",
    "trustos_a",
    "trustos_b",
    "uboot_a",
    "uboot_b",
    "teecfg_a",
    "teecfg_b",
    "nr_factorynv",
    "nr_runtimenv1",
    "nr_runtimenv2",
    "nr_downloadnv_a",
    "nr_downloadnv_b",
})


def trigger_zte_webui_reboot(
    password: str,
    host: str = "http://192.168.0.1:8080",
    timeout_sec: float = 25.0,
) -> dict[str, Any]:
    """Authenticate against ZTE stock WebUI (goform) and issue REBOOT_DEVICE for --kickto 2 capture."""
    if not password:
        raise ValueError("Explicit --webui-password required when triggering ZTE WebUI reboot")

    def sha_u(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest().upper()

    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def zget(cmd: str) -> dict[str, Any]:
        url = f"{host}/goform/goform_get_cmd_process?isTest=false&multi_data=1&cmd={urllib.parse.quote(cmd)}"
        req = urllib.request.Request(url, headers={"Referer": f"{host}/index.html"})
        with opener.open(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))

    def zpost(data: dict[str, str]) -> dict[str, Any]:
        body = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(
            f"{host}/goform/goform_set_cmd_process",
            data=body,
            headers={
                "Referer": f"{host}/index.html",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "X-Requested-With": "XMLHttpRequest",
            },
        )
        with opener.open(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))

    info = None
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        try:
            info = zget("loginfo,LD,RD,wa_inner_version,cr_version")
            if info.get("LD"):
                break
        except Exception:
            time.sleep(1.0)
    if not info or not info.get("LD"):
        raise RuntimeError(f"Stock WebUI unreachable at {host}")

    login_hash = sha_u(sha_u(password) + info["LD"])
    login_res = zpost({"isTest": "false", "goformId": "LOGIN", "password": login_hash})
    if str(login_res.get("result")) not in ("0", "4"):
        raise RuntimeError(f"WebUI login failed: {login_res}")

    rd = zget("RD")["RD"]
    ad = sha_u(sha_u(info.get("wa_inner_version", "") + info.get("cr_version", "")) + rd)
    reb = zpost({"isTest": "false", "goformId": "REBOOT_DEVICE", "AD": ad})
    return {"cr_version": info.get("cr_version"), "reboot_response": reb}


def parse_partition_xml(xml_path: Path) -> dict[str, int]:
    """Return ordered partition name -> byte capacity from spd_dump partition_list.xml.

    spd_dump stores sizes in MiB (1..65535) or 0xffffffff for userdata fill-to-end.
    """
    root = ET.parse(xml_path).getroot()
    out: dict[str, int] = {}
    for elem in root.iter("Partition"):
        raw = int(elem.attrib["size"], 0)
        if raw == 0xFFFFFFFF:
            out[elem.attrib["id"]] = 0
        elif raw < 1048576:
            out[elem.attrib["id"]] = raw * (1 << 20)
        else:
            out[elem.attrib["id"]] = raw
    return out


def verify_backup_dir(backup_dir: Path, *, require_complete_table: bool = True) -> dict[str, Any]:
    """Verify full BROM backup completeness, exact byte sizes, misc BCAB CRC, and write SHA256SUMS.txt."""
    xml_path = backup_dir / "partition_list.xml"
    errors: list[str] = []
    warnings: list[str] = []
    if not xml_path.is_file():
        raise FileNotFoundError(f"Missing {xml_path}")

    table = parse_partition_xml(xml_path)
    missing_core = sorted(p for p in CORE_PARTITIONS if p not in table)
    if missing_core:
        errors.append(f"Missing core partitions in table: {missing_core}")

    # Zero-byte or virtual/userdata partitions normally omitted by 'r all'
    optional_excluded = {"userdata", "cache", "blackbox", "splloader_bak"}
    sums_lines: list[str] = []
    checked_bytes = 0
    checked_files = 0
    empty_b_slots: dict[str, bool] = {}

    for part, expected_sz in table.items():
        fpath = backup_dir / part
        if not fpath.is_file():
            if part in optional_excluded or expected_sz == 0:
                warnings.append(f"Excluded/optional partition not dumped: {part}")
            elif require_complete_table:
                errors.append(f"Missing dumped partition: {part} (expected {expected_sz} B)")
            continue
        actual_sz = fpath.stat().st_size
        if part in CHSIZE_OR_TRIM_PARTITIONS:
            if actual_sz == 0 or (expected_sz > 0 and actual_sz > expected_sz):
                errors.append(f"{part} size {actual_sz} outside (0, {expected_sz}]")
            elif expected_sz > 0 and actual_sz < expected_sz:
                warnings.append(f"{part} trimmed to signed/NV payload {actual_sz} B (< {expected_sz} B)")
        elif actual_sz != expected_sz and expected_sz > 0:
            errors.append(f"{part} byte count {actual_sz} != table {expected_sz}")
        digest = sha256_file(fpath)
        sums_lines.append(f"{digest}  {part}")
        checked_bytes += actual_sz
        checked_files += 1
        if part in ("boot_b", "vendor_boot_b", "init_boot_b"):
            with fpath.open("rb") as fh:
                head = fh.read(65536)
            empty_b_slots[part] = not any(head)

    spl_path = backup_dir / "splloader"
    if "splloader" not in table:
        if spl_path.is_file() and spl_path.stat().st_size > 0:
            sums_lines.append(f"{sha256_file(spl_path)}  splloader")
            checked_bytes += spl_path.stat().st_size
            checked_files += 1
        elif require_complete_table:
            errors.append("Missing dumped splloader (eMMC boot0)")

    spl_bak_path = backup_dir / "splloader_bak"
    spl_bak_present = spl_bak_path.is_file() and spl_bak_path.stat().st_size > 0
    if not spl_bak_present:
        warnings.append(
            "splloader_bak (eMMC boot1) not captured by 'r all'; bare-metal SPRD3 recovery is NOT bundled (requires external signed UMS9632 FDL1/FDL2)"
        )

    misc_info = None
    misc_path = backup_dir / "misc"
    if misc_path.is_file():
        misc_info = parse_boot_control(misc_path.read_bytes())

    (backup_dir / "SHA256SUMS.txt").write_text("\n".join(sums_lines) + "\n", encoding="utf-8")
    report = {
        "checks_passed": not errors,
        "backup_dir": str(backup_dir),
        "checked_files": checked_files,
        "checked_bytes": checked_bytes,
        "recovery_channel": "SPRD4:AutoD (U-Boot autodloader; requires functional SPL + U-Boot)",
        "bare_metal_sprd3_ready": False,
        "splloader_bak_present": spl_bak_present,
        "misc": misc_info,
        "empty_b_slots": empty_b_slots,
        "errors": errors,
        "warnings": warnings,
    }
    write_json(backup_dir / "verification_report.json", report)
    if errors:
        raise ValueError(f"Backup verification failed: {errors}")
    return report


def discover_termux_usb_device() -> str:
    """List OTG USB device paths exposed by Termux:API (`termux-usb -l`)."""
    tusb = shutil.which("termux-usb")
    if not tusb:
        raise FileNotFoundError("termux-usb not found. Install Termux:API (`pkg install termux-api`) and Termux:API app.")
    res = subprocess.run([tusb, "-l"], capture_output=True, text=True, timeout=15)
    if res.returncode != 0:
        raise RuntimeError(f"termux-usb -l failed ({res.returncode}): {res.stderr or res.stdout}")
    devs = json.loads(res.stdout.strip() or "[]")
    if not devs:
        raise RuntimeError(
            "No USB OTG device returned by `termux-usb -l`. Connect F50 Pro already in 1782:4d00 autodloader mode."
        )
    if len(devs) > 1:
        raise RuntimeError(f"Multiple OTG USB devices found ({devs}); specify one explicitly with --usb-dev")
    return str(devs[0])


def _strip_kick_wait_args(args: list[str]) -> list[str]:
    """Strip --wait <N> and --kickto <N> flags incompatible with Android --usb-fd non-root mode."""
    out: list[str] = []
    i = 0
    while i < len(args):
        if args[i] in ("--wait", "--kickto"):
            i += 2
            continue
        if args[i] == "--kick":
            i += 1
            continue
        out.append(args[i])
        i += 1
    return out


def build_spd_invocation(
    tools_dir: Path,
    spd_args: list[str],
    *,
    spd_mode: str = "auto",
    usb_dev: str | None = None,
) -> tuple[list[str], dict[str, Any]]:
    """Construct cross-platform command list for spd_dump (direct, sudo, Android su, or termux-usb --usb-fd)."""
    plat = detect_host_platform()
    mode = spd_mode
    if mode == "auto":
        if plat == "android-arm64":
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                mode = "direct"
            elif shutil.which("su"):
                mode = "su"
            elif shutil.which("termux-usb"):
                mode = "termux-usb"
            else:
                mode = "direct"
        else:
            mode = "direct"

    if mode == "direct":
        spd = resolve_tool("spd_dump", tools_dir, platform_id=plat)
        return [str(spd), *spd_args], {"platform": plat, "mode": "direct", "binary": str(spd)}

    if mode == "sudo":
        if plat == "win64":
            spd = resolve_tool("spd_dump", tools_dir, platform_id=plat)
            return [str(spd), *spd_args], {"platform": plat, "mode": "direct", "binary": str(spd)}
        spd = resolve_tool("spd_dump", tools_dir, platform_id=plat)
        return ["sudo", str(spd), *spd_args], {"platform": plat, "mode": "sudo", "binary": str(spd)}

    if mode == "su":
        spd = resolve_tool("spd_dump", tools_dir, platform_id="android-arm64", prefer_variant="su")
        inner = shlex.join([str(spd), *spd_args])
        return ["su", "-c", inner], {"platform": plat, "mode": "su", "binary": str(spd)}

    if mode == "termux-usb":
        tusb = shutil.which("termux-usb")
        if not tusb:
            raise FileNotFoundError("termux-usb not found in PATH")
        spd = resolve_tool("spd_dump", tools_dir, platform_id="android-arm64", prefer_variant="termux-usb")
        target_dev = usb_dev or discover_termux_usb_device()
        fd_args = _strip_kick_wait_args(spd_args)
        inner_cmd = shlex.join([str(spd), "--usb-fd", *fd_args])
        return [tusb, "-e", inner_cmd, target_dev], {
            "platform": plat,
            "mode": "termux-usb",
            "binary": str(spd),
            "usb_dev": target_dev,
            "requires_pre_autodloader": True,
        }

    raise ValueError(f"Unsupported --spd-mode '{spd_mode}'; choose auto, direct, sudo, su, or termux-usb")


def _explain_libusb_error(line: str, launch_meta: dict[str, Any]) -> str:
    if "LIBUSB_ERROR_ACCESS" in line:
        plat = launch_meta.get("platform", "")
        if plat == "macos":
            return f"{line} (macOS requires root USB permission: re-run with sudo or `--spd-mode sudo`)"
        if plat in ("linux-x64", "linux-arm64"):
            return f"{line} (Linux USB permission denied: install assets/udev/99-unisoc-f50pro.rules or use `--spd-mode sudo`)"
        if plat == "android-arm64":
            return f"{line} (Android USB permission denied: use Root `--spd-mode su`, or enter 1782:4d00 first with `--spd-mode termux-usb`)"
    return line


def run_brom_backup(
    output_dir: Path,
    *,
    tools_dir: Path = DEFAULT_TOOLS_DIR,
    wait_sec: int = 120,
    webui_password: str | None = None,
    webui_host: str = "http://192.168.0.1:8080",
    spd_mode: str = "auto",
    usb_dev: str | None = None,
) -> dict[str, Any]:
    """Execute read-only SPRD4:AutoD dump ('r all reset') and verify every partition."""
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / "spd_dump_backup.log"

    spd_args = [
        "--wait",
        str(wait_sec),
        "--kickto",
        "2",
        "--verbose",
        "1",
        "path",
        str(output_dir),
        "partition_list",
        str(output_dir / "partition_list.xml"),
        "r",
        "all",
        "reset",
    ]
    cmd, launch_meta = build_spd_invocation(tools_dir, spd_args, spd_mode=spd_mode, usb_dev=usb_dev)
    proc = subprocess.Popen(
        cmd,
        cwd=output_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        **win_no_window_kwargs(),
    )

    lines: queue.Queue[str | None] = queue.Queue()

    def _reader() -> None:
        assert proc.stdout
        with log_path.open("w", encoding="utf-8") as lf:
            for line in proc.stdout:
                lf.write(line)
                lf.flush()
                lines.put(line)
        lines.put(None)

    threading.Thread(target=_reader, daemon=True).start()
    boot_diag_seen = False
    deadline = time.monotonic() + wait_sec + 900
    tail: list[str] = []
    while time.monotonic() < deadline:
        try:
            item = lines.get(timeout=1.0)
        except queue.Empty:
            if proc.poll() is not None:
                break
            continue
        if item is None:
            break
        tail.append(item.strip())
        if len(tail) > 25:
            tail.pop(0)
        if not boot_diag_seen and "Waiting for boot_diag" in item:
            boot_diag_seen = True
            if webui_password:
                time.sleep(0.8)
                trigger_zte_webui_reboot(webui_password, host=webui_host)
        if FATAL_SPD_RE.search(item) and "Waiting" not in item:
            proc.terminate()
            raise RuntimeError(f"spd_dump fatal error: {_explain_libusb_error(item.strip(), launch_meta)}")

    rc = proc.wait(timeout=30)
    if rc != 0:
        raise RuntimeError(f"spd_dump backup failed rc={rc} mode={launch_meta['mode']}; tail={tail[-10:]}")
    rep = verify_backup_dir(output_dir, require_complete_table=True)
    rep["spd_launch"] = launch_meta
    return rep


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    parser.add_argument("--wait-sec", type=int, default=120)
    parser.add_argument("--webui-password", help="Stock WebUI password for automatic REBOOT_DEVICE trigger")
    parser.add_argument("--webui-host", default="http://192.168.0.1:8080")
    parser.add_argument("--spd-mode", default="auto", choices=["auto", "direct", "sudo", "su", "termux-usb"])
    parser.add_argument("--usb-dev", help="Explicit Termux OTG /dev/bus/usb/XXX/YYY path for --spd-mode termux-usb")
    args = parser.parse_args()

    out_dir = args.output_dir if args.output_dir.is_absolute() else (REPO_ROOT / args.output_dir)
    if args.verify_only:
        res = verify_backup_dir(out_dir, require_complete_table=True)
    else:
        res = run_brom_backup(
            out_dir,
            tools_dir=args.tools_dir,
            wait_sec=args.wait_sec,
            webui_password=args.webui_password,
            webui_host=args.webui_host,
            spd_mode=args.spd_mode,
            usb_dev=args.usb_dev,
        )
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
