"""Read-only end-to-end verification across host network isolation, OpenWrt _b, and Android _a."""
from __future__ import annotations

import argparse
import json
import subprocess
import urllib.request
from pathlib import Path
from typing import Any

from common import DEFAULT_TOOLS_DIR, REPO_ROOT, resolve_tool, win_no_window_kwargs, write_json
from host_network import audit_default_routes
from provision_openwrt import connect_ssh, ssh_run


def _probe_openwrt(host: str, passwords: tuple[str, ...], check_openclash: bool) -> dict[str, Any]:
    report: dict[str, Any] = {"reachable": False}
    try:
        ssh = connect_ssh(host, passwords=passwords, timeout=5.0)
    except Exception as exc:
        report["error"] = str(exc)
        return report

    try:
        _, out, _ = ssh_run(
            ssh,
            "printf 'model=%s\\nboard_id=%s\\nslot=%s\\n' "
            "\"$(cat /etc/mu300/model 2>/dev/null)\" "
            "\"$(cat /proc/driver/board_id 2>/dev/null)\" "
            "\"$(uci -q get unisoc_modem.main.wifi_device)\" && "
            "df -B1 / | tail -n 1 && "
            "uci -q get unisoc_modem.main.f50pro_button_long || true",
            check=False,
        )
        report["reachable"] = True
        report["ssh_probe"] = out.strip().splitlines()
        if check_openclash:
            _, oc_out, _ = ssh_run(ssh, "ss -tln | grep ':9090 ' || true", check=False)
            report["openclash_9090_listening"] = ":9090" in oc_out
    finally:
        ssh.close()

    try:
        with urllib.request.urlopen(f"http://{host}/", timeout=5) as resp:
            report["luci_http_status"] = resp.status
    except Exception as exc:
        report["luci_http_error"] = str(exc)
    return report


def _probe_android(adb_exe: Path | None, *, serial: str | None = None) -> dict[str, Any]:
    if adb_exe is None:
        return {"reachable": False, "reason": "adb not available"}
    base = [str(adb_exe), "-s", serial] if serial else [str(adb_exe)]
    if serial and ":" in serial:
        subprocess.run([str(adb_exe), "connect", serial], capture_output=True, text=True, timeout=5, **win_no_window_kwargs())
    res = subprocess.run(
        [*base, "get-state"],
        capture_output=True,
        text=True,
        timeout=5,
        **win_no_window_kwargs(),
    )
    if res.returncode != 0 or res.stdout.strip() != "device":
        return {"reachable": False}
    info: dict[str, Any] = {"reachable": True}
    for key, args in (
        ("slot_suffix", ["shell", "getprop", "ro.boot.slot_suffix"]),
        ("usb_config", ["shell", "getprop", "persist.sys.usb.config"]),
        ("su_id", ["shell", "su", "-c", "id -u"]),
        ("ports", ["shell", "su", "-c", "ss -tln | grep -E ':(2333|1146) ' || true"]),
    ):
        r = subprocess.run(
            [*base, *args],
            capture_output=True,
            text=True,
            timeout=10,
            **win_no_window_kwargs(),
        )
        info[key] = r.stdout.strip()
    return info


def verify_environment(
    *,
    openwrt_host: str = "192.168.77.1",
    root_password: str | None = None,
    tools_dir: Path = DEFAULT_TOOLS_DIR,
    check_openclash: bool = False,
    serial: str | None = None,
    out_path: Path | None = None,
) -> dict[str, Any]:
    """Audit host gateway isolation plus active OpenWrt and/or Android runtime health."""
    pws = (root_password, "", "root") if root_password else ("", "root")
    try:
        adb_exe: Path | None = resolve_tool("adb", tools_dir)
    except FileNotFoundError:
        adb_exe = None

    report = {
        "host_routes": audit_default_routes(),
        "openwrt": _probe_openwrt(openwrt_host, pws, check_openclash),
        "android": _probe_android(adb_exe, serial=serial),
    }
    if out_path is not None:
        write_json(out_path, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openwrt-host", default="192.168.77.1")
    parser.add_argument("--root-password")
    parser.add_argument("--openclash", action="store_true")
    parser.add_argument("--adb-serial")
    parser.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    out = (args.out if args.out.is_absolute() else (REPO_ROOT / args.out)) if args.out else None
    rep = verify_environment(
        openwrt_host=args.openwrt_host,
        root_password=args.root_password,
        tools_dir=args.tools_dir,
        check_openclash=args.openclash,
        serial=args.adb_serial,
        out_path=out,
    )
    print(json.dumps(rep, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
