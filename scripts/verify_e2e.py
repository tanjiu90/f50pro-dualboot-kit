"""Profile-aware E2E verification with real boot slot evidence, PASS/FAIL/NOT_TESTED/NOT_APPLICABLE states, and non-zero failure exit."""
from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

_ORIG_URLOPEN = urllib.request.urlopen


class _SameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Allow redirects only within the same target router host (never off-device)."""

    def __init__(self, expected_host: str) -> None:
        super().__init__()
        self._expected_host = expected_host.lower()

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlparse(newurl)
        if target.hostname and target.hostname.lower() != self._expected_host:
            raise urllib.error.URLError(f"Refused off-host redirect to {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

from common import (
    DEFAULT_TOOLS_DIR,
    PROFILES,
    REPO_ROOT,
    AuthContext,
    resolve_auth_context,
    resolve_tool,
    win_no_window_kwargs,
    write_json,
)
from host_network import audit_default_routes
from provision_android import resolve_android_su_bin
from provision_openwrt import connect_ssh, ssh_run


def _redact_secret(text: str, secret: str | None) -> str:
    if secret:
        return text.replace(secret, "***REDACTED***")
    return text


def _parse_openwrt_boot_evidence(out: str) -> dict[str, Any]:
    """Parse real boot evidence (cmdline / bootargs) without ever using wifi_device as a slot name."""
    fields: dict[str, str] = {}
    df_line = ""
    for line in out.splitlines():
        if "=" in line and line.split("=", 1)[0] in (
            "model",
            "board_id",
            "wifi_device",
            "cmdline",
            "bootargs",
            "openwrt_id",
            "button_long",
            "usb_get",
            "usb_mode",
        ):
            k, v = line.split("=", 1)
            fields[k] = v.strip()
        elif line.startswith("/"):
            df_line = line.strip()

    evidence_text = f"{fields.get('cmdline', '')} {fields.get('bootargs', '')}"
    m_slot = re.search(r"(?:(?:androidboot|sprdboot)\.)?slot_suffix=(_[ab])\b", evidence_text)
    slot_suffix = m_slot.group(1) if m_slot else "UNKNOWN"
    board_id = fields.get("board_id") or ""
    if not board_id or board_id.upper() == "UNKNOWN":
        m_board = re.search(r"\bzteboot\.zte_boardid=(\d+)\b", evidence_text)
        if m_board:
            board_id = m_board.group(1)
    active_os = "openwrt" if fields.get("model") == "f50pro" and fields.get("openwrt_id") else "UNKNOWN"
    usb_mode = fields.get("usb_mode") or ""
    usb_get_raw = fields.get("usb_get") or ""
    if usb_get_raw.startswith("{"):
        try:
            ujson = json.loads(usb_get_raw)
            live_mode = str(ujson.get("net_current") or ujson.get("net_mode") or "").strip().lower()
            if live_mode and live_mode != "unknown":
                usb_mode = live_mode
        except json.JSONDecodeError:
            pass
    out_info = {
        "model": fields.get("model") or "UNKNOWN",
        "board_id": board_id or "UNKNOWN",
        "wifi_device": fields.get("wifi_device") or "UNKNOWN",
        "slot_suffix": slot_suffix,
        "slot_evidence_source": "/proc/cmdline|bootargs" if m_slot else "UNAVAILABLE",
        "active_os": active_os,
        "button_long": fields.get("button_long") or "",
        "rootfs_df": df_line,
    }
    if usb_mode:
        out_info["usb_mode"] = usb_mode
    return out_info


def _probe_openwrt(host: str, auth_ctx: AuthContext, check_openclash: bool) -> dict[str, Any]:
    report: dict[str, Any] = {
        "reachable": False,
        "auth_failed": False,
        "active_os": "UNKNOWN",
        "slot_suffix": "UNKNOWN",
    }
    try:
        ssh = connect_ssh(host, username=auth_ctx.username, passwords=auth_ctx.candidate_passwords(), timeout=5.0)
    except Exception as exc:
        msg = _redact_secret(str(exc), auth_ctx.password)
        report["error"] = msg
        if any(tok in msg.lower() for tok in ("authentication", "auth", "permission denied", "bad authentication")):
            report["auth_failed"] = True
        return report

    try:
        _, out, _ = ssh_run(
            ssh,
            "printf 'model=%s\\nboard_id=%s\\nwifi_device=%s\\nopenwrt_id=%s\\ncmdline=%s\\nbootargs=%s\\nbutton_long=%s\\nusb_get=%s\\nusb_mode=%s\\n' "
            "\"$(cat /etc/mu300/model 2>/dev/null)\" "
            "\"$(cat /proc/driver/board_id 2>/dev/null)\" "
            "\"$(uci -q get unisoc_modem.main.wifi_device 2>/dev/null)\" "
            "\"$(grep -m1 '^DISTRIB_ID=' /etc/openwrt_release 2>/dev/null | cut -d= -f2 | tr -d \"'\\\"\")\" "
            "\"$(tr '\\r\\n' '  ' </proc/cmdline 2>/dev/null)\" "
            "\"$(tr '\\0\\r\\n' '   ' </proc/device-tree/chosen/bootargs 2>/dev/null)\" "
            "\"$(uci -q get unisoc_modem.main.f50pro_button_long 2>/dev/null)\" "
            "\"$(/usr/libexec/unisoc-modem/device-usb get 2>/dev/null || true)\" "
            "\"$(m=$(sed -n 's/^mode=//p' /etc/unisoc-modem/usb-boot.conf 2>/dev/null | head -n 1); [ -n \"$m\" ] && printf '%s' \"$m\" || uci -q get u30pro.usb.mode || true)\" && "
            "(df -k / /mnt/mu300-disk 2>/dev/null || df /) | tail -n 1",
            check=False,
        )
        parsed = _parse_openwrt_boot_evidence(out)
        report["reachable"] = True
        report.update(parsed)
        if check_openclash:
            oc_rc, oc_out, _ = ssh_run(
                ssh,
                "L_SOCK=\"$( (command -v ss >/dev/null 2>&1 && ss -tuln || netstat -lunt) 2>/dev/null || true )\"; "
                "printf 'p9090=%s\\np7874=%s\\ndns_srv=%s\\ncfg=%s\\n' "
                "\"$(printf '%s\\n' \"$L_SOCK\" | grep -E '(:|:::)9090([[:space:]]|$)' | head -n 1)\" "
                "\"$(printf '%s\\n' \"$L_SOCK\" | grep -E '(:|:::)7874([[:space:]]|$)' | head -n 1)\" "
                "\"$(uci -q get dhcp.@dnsmasq[0].server 2>/dev/null || true)\" "
                "\"$(uci -q get openclash.config.config_path 2>/dev/null || true)\"",
                check=False,
            )
            oc_fields: dict[str, str] = {}
            for ln in oc_out.splitlines():
                if "=" in ln:
                    k, v = ln.split("=", 1)
                    oc_fields[k.strip()] = v.strip()
            has_structured = "p9090" in oc_fields or "dns_srv" in oc_fields
            has_9090 = (":9090" in oc_fields.get("p9090", "")) or (":9090" in oc_out and not has_structured)
            has_7874 = ":7874" in oc_fields.get("p7874", "")
            dns_srv = oc_fields.get("dns_srv", "")
            dns_points_7874 = "#7874" in dns_srv
            report["openclash_9090_listening"] = has_9090
            report["openclash_dns_7874_listening"] = has_7874
            report["openclash_dnsmasq_servers"] = dns_srv
            report["openclash_config_path"] = oc_fields.get("cfg", "")
            if oc_rc != 0 or not oc_out.strip():
                report["openclash_dns_ok"] = False
            else:
                report["openclash_dns_ok"] = (not dns_points_7874) or has_7874
    finally:
        ssh.close()

    try:
        url = f"http://{host}/"
        if urllib.request.urlopen is _ORIG_URLOPEN:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                _SameHostRedirectHandler(host),
            )
            with opener.open(url, timeout=5) as resp:
                report["luci_http_status"] = resp.status
        else:
            with urllib.request.urlopen(url, timeout=5) as resp:
                report["luci_http_status"] = resp.status
    except urllib.error.HTTPError as exc:
        report["luci_http_status"] = exc.code
        if exc.code == 403:
            try:
                body = exc.read(4096).decode("utf-8", errors="replace").lower()
            except Exception:
                body = ""
            report["luci_login_detected"] = any(tok in body for tok in ("luci", "sysauth", "openwrt"))
    except Exception as exc:
        report["luci_http_error"] = str(exc)
    return report


def _probe_android(adb_exe: Path | None, *, serial: str | None = None) -> dict[str, Any]:
    if adb_exe is None:
        return {"reachable": False, "slot_suffix": "UNKNOWN", "active_os": "UNKNOWN", "reason": "adb not available"}
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
        return {"reachable": False, "slot_suffix": "UNKNOWN", "active_os": "UNKNOWN"}

    info: dict[str, Any] = {"reachable": True, "active_os": "android"}
    su_bin = resolve_android_su_bin(adb_exe, serial=serial)
    q_id = shlex.quote("id -u")
    q_ports = shlex.quote("ss -tln | grep -E ':(2333|1146) ' || true")
    for key, args in (
        ("slot_suffix", ["shell", "getprop", "ro.boot.slot_suffix"]),
        ("boot_completed", ["shell", "getprop", "sys.boot_completed"]),
        ("usb_config", ["shell", "getprop", "persist.sys.usb.config"]),
        ("su_id", ["shell", f"{su_bin} -c {q_id}"]),
        ("ports", ["shell", f"{su_bin} -c {q_ports}"]),
    ):
        r = subprocess.run(
            [*base, *args],
            capture_output=True,
            text=True,
            timeout=10,
            **win_no_window_kwargs(),
        )
        info[key] = r.stdout.strip()
    if info.get("slot_suffix") not in ("_a", "_b"):
        info["slot_suffix"] = "UNKNOWN"
    return info


def evaluate_e2e_checks(
    *,
    profile_id: str | None,
    host_routes: dict[str, Any],
    openwrt: dict[str, Any],
    android: dict[str, Any],
    check_openclash: bool = False,
    expected_active_os: str = "auto",
) -> dict[str, Any]:
    """Classify each profile-relevant verification gate strictly as PASS, FAIL, NOT_TESTED, or NOT_APPLICABLE."""
    checks: dict[str, dict[str, Any]] = {}

    def _rec(status: str, detail: str = "") -> dict[str, Any]:
        return {"status": status, "detail": detail}

    prof = PROFILES.get(profile_id) if profile_id else None
    need_ow = prof["openwrt"] if prof else True
    need_and = prof["android_root"] if prof else True

    if host_routes.get("usb_default_route_leak"):
        checks["host_route_isolation"] = _rec("FAIL", "USB default gateway leak detected")
    elif prof and not need_ow:
        checks["host_route_isolation"] = _rec(
            "NOT_APPLICABLE",
            "Profile does not configure or isolate OpenWrt USB host interface (no leak observed)",
        )
    elif host_routes.get("audit_incomplete") or "missing" in str(host_routes.get("warning", "")).lower():
        checks["host_route_isolation"] = _rec(
            "FAIL",
            f"Host route audit incomplete: {host_routes.get('warning') or 'missing route inspection tool'}",
        )
    else:
        checks["host_route_isolation"] = _rec("PASS", "No host route leak")

    if expected_active_os not in ("auto", "openwrt", "android"):
        raise ValueError(f"Invalid expected_active_os={expected_active_os!r}")

    ow_reachable = bool(openwrt.get("reachable"))
    an_reachable = bool(android.get("reachable"))

    # Determine which dual-boot side is currently expected to respond live
    if expected_active_os == "openwrt":
        test_ow, test_an = True, False
    elif expected_active_os == "android":
        test_ow, test_an = False, True
    elif prof and prof["openwrt"] and prof["android_root"]:
        # Profile 3 (3-dual-full): whichever slot is currently booted is actively required; the other cannot respond simultaneously.
        if ow_reachable and not an_reachable:
            test_ow, test_an = True, False
        elif an_reachable and not ow_reachable:
            test_ow, test_an = False, True
        else:
            test_ow, test_an = True, True
    else:
        test_ow, test_an = need_ow, need_and

    # 1. OpenWrt checks
    if not need_ow:
        checks["openwrt_ssh"] = _rec("NOT_APPLICABLE", "Profile does not include OpenWrt")
        checks["openwrt_slot_b"] = _rec("NOT_APPLICABLE", "Profile does not include OpenWrt")
        checks["openwrt_luci"] = _rec("NOT_APPLICABLE", "Profile does not include OpenWrt")
        checks["openclash_9090"] = _rec("NOT_APPLICABLE", "Profile does not include OpenWrt")
    elif not test_ow:
        checks["openwrt_ssh"] = _rec("NOT_TESTED", "Target is currently booted into Android _a")
        checks["openwrt_slot_b"] = _rec("NOT_TESTED", "Target is currently booted into Android _a")
        checks["openwrt_luci"] = _rec("NOT_TESTED", "Target is currently booted into Android _a")
        checks["openclash_9090"] = _rec("NOT_TESTED" if check_openclash else "NOT_APPLICABLE", "Inactive slot")
    else:
        if not ow_reachable:
            reason = "SSH authentication failed" if openwrt.get("auth_failed") else str(openwrt.get("error") or "OpenWrt unreachable")
            checks["openwrt_ssh"] = _rec("FAIL", reason)
            checks["openwrt_slot_b"] = _rec("FAIL", "OpenWrt SSH unavailable")
            checks["openwrt_luci"] = _rec("FAIL", "OpenWrt unreachable")
            checks["openclash_9090"] = _rec("FAIL" if check_openclash else "NOT_APPLICABLE", "OpenWrt unreachable")
        else:
            model_val = openwrt.get("model")
            model_ok = (model_val == "f50pro") if ("model" in openwrt) else (openwrt.get("active_os") == "openwrt")
            checks["openwrt_ssh"] = _rec(
                "PASS" if model_ok else "FAIL",
                f"active_os={openwrt.get('active_os')} model={model_val}" if "model" in openwrt else f"active_os={openwrt.get('active_os')}",
            )
            slot_b_ok = openwrt.get("slot_suffix") == "_b"
            checks["openwrt_slot_b"] = _rec(
                "PASS" if slot_b_ok else "FAIL",
                f"slot_suffix={openwrt.get('slot_suffix', 'UNKNOWN')}",
            )
            luci_status = openwrt.get("luci_http_status")
            luci_login = openwrt.get("luci_login_detected")
            luci_ok = luci_status in (200, 302) or (luci_status == 403 and luci_login is True)
            luci_detail = f"http_status={luci_status or openwrt.get('luci_http_error')}"
            if luci_status == 403:
                luci_detail += " (luci_login_detected=true)" if luci_login is True else " (403 without LuCI login page)"
            checks["openwrt_luci"] = _rec(
                "PASS" if luci_ok else "FAIL",
                luci_detail,
            )
            if check_openclash:
                oc_9090 = bool(openwrt.get("openclash_9090_listening"))
                oc_dns_ok = openwrt.get("openclash_dns_ok", True) is not False
                oc_ok = oc_9090 and oc_dns_ok
                detail = "Port 9090 listening and DNS consistent"
                if not oc_9090:
                    detail = "Port 9090 NOT listening"
                elif not oc_dns_ok:
                    detail = "dnsmasq forwards to OpenClash DNS #7874 which is NOT listening"
                checks["openclash_9090"] = _rec("PASS" if oc_ok else "FAIL", detail)
            else:
                checks["openclash_9090"] = _rec("NOT_APPLICABLE", "OpenClash check not requested")

    # 2. Android Root / UFI-TOOLS checks
    if not need_and:
        checks["android_adb"] = _rec("NOT_APPLICABLE", "Profile leaves stock Android untouched / not required")
        checks["android_slot_a"] = _rec("NOT_APPLICABLE", "Profile does not require Android root checks")
        checks["android_su_root"] = _rec("NOT_APPLICABLE", "Profile does not require Android root checks")
        checks["android_ufi_services"] = _rec("NOT_APPLICABLE", "Profile does not require UFI-TOOLS")
    elif not test_an:
        checks["android_adb"] = _rec("NOT_TESTED", "Target is currently booted into OpenWrt _b")
        checks["android_slot_a"] = _rec("NOT_TESTED", "Target is currently booted into OpenWrt _b")
        checks["android_su_root"] = _rec("NOT_TESTED", "Target is currently booted into OpenWrt _b")
        checks["android_ufi_services"] = _rec("NOT_TESTED", "Target is currently booted into OpenWrt _b")
    else:
        if not an_reachable:
            checks["android_adb"] = _rec("FAIL", str(android.get("reason") or "Android ADB unreachable"))
            checks["android_slot_a"] = _rec("FAIL", "Android ADB unavailable")
            checks["android_su_root"] = _rec("FAIL", "Android ADB unavailable")
            checks["android_ufi_services"] = _rec("FAIL", "Android ADB unavailable")
        else:
            checks["android_adb"] = _rec("PASS", "ADB device online")
            slot_a_ok = android.get("slot_suffix") == "_a"
            checks["android_slot_a"] = _rec("PASS" if slot_a_ok else "FAIL", f"slot_suffix={android.get('slot_suffix')}")
            su_ok = str(android.get("su_id", "")).strip() == "0"
            checks["android_su_root"] = _rec("PASS" if su_ok else "FAIL", f"su_id={android.get('su_id')!r}")
            ports_txt = str(android.get("ports", ""))
            ports_ok = (":2333" in ports_txt) and (":1146" in ports_txt)
            checks["android_ufi_services"] = _rec("PASS" if ports_ok else "FAIL", "Ports :2333/:1146 listening" if ports_ok else f"Missing listening ports ({ports_txt!r})")

    any_fail = any(c["status"] == "FAIL" for c in checks.values())
    any_target_pass = any(k != "host_route_isolation" and c["status"] == "PASS" for k, c in checks.items())
    overall_status = "FAIL" if (any_fail or not any_target_pass) else "PASS"
    return {
        "overall_status": overall_status,
        "checks": checks,
    }


def verify_environment(
    *,
    openwrt_host: str = "192.168.77.1",
    root_password: str | None = None,
    auth_context: AuthContext | None = None,
    credentials_file: Path | None = None,
    profile_id: str | None = None,
    expected_active_os: str = "auto",
    tools_dir: Path = DEFAULT_TOOLS_DIR,
    check_openclash: bool = False,
    serial: str | None = None,
    out_path: Path | None = None,
) -> dict[str, Any]:
    """Audit host gateway isolation plus active OpenWrt and/or Android runtime health cleanly."""
    ctx = auth_context or resolve_auth_context(
        explicit_password=root_password,
        credentials_file=credentials_file,
        host=openwrt_host,
    )
    try:
        adb_exe: Path | None = resolve_tool("adb", tools_dir)
    except FileNotFoundError:
        adb_exe = None

    include_android_usb = bool(profile_id and PROFILES.get(profile_id, {}).get("android_root"))
    host_routes = audit_default_routes(include_zte_android=include_android_usb)
    ow = _probe_openwrt(openwrt_host, ctx, check_openclash)
    an = _probe_android(adb_exe, serial=serial)
    verdict = evaluate_e2e_checks(
        profile_id=profile_id,
        host_routes=host_routes,
        openwrt=ow,
        android=an,
        check_openclash=check_openclash,
        expected_active_os=expected_active_os,
    )

    report = {
        "overall_status": verdict["overall_status"],
        "profile": profile_id,
        "auth_context": ctx.to_public_metadata(),
        "checks": verdict["checks"],
        "host_routes": host_routes,
        "openwrt": ow,
        "android": an,
    }
    if out_path is not None:
        write_json(out_path, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openwrt-host", default="192.168.77.1")
    parser.add_argument("--root-password")
    parser.add_argument("--credentials-file", type=Path)
    parser.add_argument("--profile", choices=list(PROFILES))
    parser.add_argument("--expected-active-os", default="auto", choices=["auto", "openwrt", "android"])
    parser.add_argument("--openclash", action="store_true")
    parser.add_argument("--adb-serial")
    parser.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    out = (args.out if args.out.is_absolute() else (REPO_ROOT / args.out)) if args.out else None
    cred = (
        args.credentials_file
        if args.credentials_file is None or args.credentials_file.is_absolute()
        else (REPO_ROOT / args.credentials_file)
    )
    rep = verify_environment(
        openwrt_host=args.openwrt_host,
        root_password=args.root_password,
        credentials_file=cred,
        profile_id=args.profile,
        expected_active_os=args.expected_active_os,
        tools_dir=args.tools_dir,
        check_openclash=args.openclash,
        serial=args.adb_serial,
        out_path=out,
    )
    print(json.dumps(rep, indent=2, ensure_ascii=False))
    return 0 if rep["overall_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
