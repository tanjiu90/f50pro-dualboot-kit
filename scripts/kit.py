"""Unified CLI and one-click turnkey entrypoint for ZTE F50 Pro (B15 & B28) dual-boot provisioning."""
from __future__ import annotations

import argparse
import importlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from brom_backup import run_brom_backup, verify_backup_dir
from build_images import build_profile
from common import (
    DEFAULT_CACHE_DIR,
    DEFAULT_TOOLS_DIR,
    MANIFEST_PATH,
    PROFILES,
    REPO_ROOT,
    AuthContext,
    detect_host_platform,
    read_json,
    resolve_auth_context,
    resolve_tool,
    write_json,
)
from fetch_assets import (
    PROFILE_PACK_MAP,
    fetch_and_extract,
    interactive_select,
    list_available_packs,
)
from flash_images import execute_flash
from host_network import audit_default_routes
from inspect_backup import inspect_backup_dir
from provision_android import provision_android
from provision_openwrt import VALID_USB_NET_MODES, provision_openwrt
from verify_e2e import verify_environment


def _rel(p: Path) -> Path:
    return p if p.is_absolute() else (REPO_ROOT / p)


def run_preflight(
    *,
    tools_dir: Path = DEFAULT_TOOLS_DIR,
    adb_pubkey: Path | None = None,
    operation: str = "all",
    profile: str | None = None,
) -> dict[str, Any]:
    """Verify host Python modules, extracted tools, ADB RSA pubkey, and route hygiene without touching devices."""
    plat = detect_host_platform()
    mods = {}
    for mod in ("paramiko", "serial", "pytest"):
        try:
            importlib.import_module(mod)
            mods[mod] = True
        except ImportError:
            mods[mod] = False

    tools: dict[str, str | None] = {}
    for t in ("spd_dump", "adb"):
        try:
            tools[t] = str(resolve_tool(t, tools_dir, platform_id=plat))
        except FileNotFoundError:
            tools[t] = None
    if plat == "android-arm64":
        try:
            tools["spd_dump_termux_usb"] = str(
                resolve_tool("spd_dump", tools_dir, platform_id=plat, prefer_variant="termux-usb")
            )
        except FileNotFoundError:
            tools["spd_dump_termux_usb"] = None

    need_android = profile is None or PROFILES.get(profile, {}).get("android_root", False)
    req_mods: tuple[str, ...] = ("paramiko",)
    req_tools: tuple[str, ...] = ("spd_dump", "adb") if need_android else ("spd_dump",)
    if operation in ("backup", "flash"):
        req_mods = ()
        req_tools = ("spd_dump",)
    elif operation == "provision-openwrt":
        req_mods = ("paramiko",)
        req_tools = ()
    elif operation == "provision-android":
        req_mods = ("paramiko",) if profile == "3-dual-full" else ()
        req_tools = ("adb",)
    elif operation in ("verify", "probe"):
        req_mods = ("paramiko",)
        req_tools = ("adb",) if (profile and need_android) else ()

    missing_modules = [m for m in req_mods if not mods.get(m)]
    missing_tools = [t for t in req_tools if not tools.get(t)]
    blocking_reasons: list[str] = []
    if missing_modules:
        blocking_reasons.append(f"Missing required Python modules: {missing_modules}")
    if missing_tools:
        blocking_reasons.append(f"Missing required host tools for {operation}: {missing_tools}")

    key_path = adb_pubkey or (Path.home() / ".android" / "adbkey.pub")
    report: dict[str, Any] = {
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "host_platform": plat,
        "operation": operation,
        "profile": profile,
        "ready": not blocking_reasons,
        "missing_modules": missing_modules,
        "missing_tools": missing_tools,
        "blocking_reasons": blocking_reasons,
        "modules": mods,
        "tools": tools,
        "adb_pubkey_present": key_path.is_file(),
        "adb_pubkey_path": str(key_path),
        "host_routes": audit_default_routes(),
        "profiles": list(PROFILES.keys()),
    }
    if plat in ("linux-x64", "linux-arm64"):
        report["linux_udev_rules_installed"] = Path("/etc/udev/rules.d/99-unisoc-f50pro.rules").is_file()
        report["is_root"] = hasattr(os, "geteuid") and os.geteuid() == 0
    elif plat == "macos":
        report["is_root"] = hasattr(os, "geteuid") and os.geteuid() == 0
    elif plat == "android-arm64":
        report["is_root"] = hasattr(os, "geteuid") and os.geteuid() == 0
        report["termux_env"] = {
            "su": shutil.which("su"),
            "termux_usb": shutil.which("termux-usb"),
            "termux_adb": shutil.which("termux-adb"),
        }
    return report


def assert_preflight_ready(
    *,
    operation: str,
    tools_dir: Path = DEFAULT_TOOLS_DIR,
    profile: str | None = None,
    adb_pubkey: Path | None = None,
) -> dict[str, Any]:
    """Fail immediately before live device actions when required host modules or tools are missing."""
    rep = run_preflight(tools_dir=tools_dir, adb_pubkey=adb_pubkey, operation=operation, profile=profile)
    if not rep["ready"]:
        raise RuntimeError(f"Preflight check failed before {operation}: {rep['blocking_reasons']}")
    return rep


def run_auto(args: argparse.Namespace) -> dict[str, Any]:
    """Execute end-to-end flow: fetch -> BROM backup -> inspect -> build -> (dry-run or flash) -> provision -> verify."""
    work_dir = _rel(args.work_dir)
    backup_dir = work_dir / "backup"
    out_dir = work_dir / "build"

    steps: dict[str, Any] = {}
    steps["fetch_assets"] = fetch_and_extract(
        include_openclash=args.openclash,
        host_platform=args.host_platform,
        profile=args.profile,
        cache_dir=args.cache_dir,
        tools_dir=args.tools_dir,
    )

    if args.reuse_backup and (backup_dir / "verification_report.json").is_file():
        steps["backup"] = verify_backup_dir(backup_dir, require_complete_table=True)
    else:
        steps["backup"] = run_brom_backup(
            backup_dir,
            tools_dir=args.tools_dir,
            webui_password=args.webui_password,
            webui_host=args.webui_host,
            spd_mode=args.spd_mode,
            usb_dev=args.usb_dev,
        )

    steps["inspect"] = inspect_backup_dir(backup_dir, out_dir / "hardware_facts.json")
    plan = build_profile(
        backup_dir=backup_dir,
        profile_id=args.profile,
        out_dir=out_dir,
        tools_dir=args.tools_dir,
        adb_pubkey_path=args.adb_pubkey,
        usb_mode=args.usb_mode,
    )
    steps["build"] = {
        "profile": plan["profile"],
        "total_brom_write_bytes": plan["total_brom_write_bytes"],
        "flash_plan": str(out_dir / "flash_plan.json"),
    }

    steps["flash"] = execute_flash(
        out_dir / "flash_plan.json",
        tools_dir=args.tools_dir,
        webui_password=args.webui_password,
        webui_host=args.webui_host,
        execute=args.execute,
        spd_mode=args.spd_mode,
        usb_dev=args.usb_dev,
    )

    if not args.execute:
        steps["next_action"] = "Review flash_plan.json, then re-run with --execute to write device flash and provision OS."
        write_json(work_dir / "auto_dry_run_report.json", steps)
        return steps

    profile = PROFILES[args.profile]
    cred_file = out_dir / "openwrt-credentials.json"
    if profile["openwrt"]:
        steps["provision_openwrt"] = provision_openwrt(
            profile_id=args.profile,
            openwrt_host=args.openwrt_host,
            wifi_ssid=args.wifi_ssid,
            wifi_password=args.wifi_password,
            root_password=args.root_password,
            generate_password=args.generate_password,
            tools_dir=args.tools_dir,
            cache_dir=args.cache_dir,
            include_openclash=args.openclash,
            isolate_host=not args.no_host_isolate,
            out_dir=out_dir,
            usb_net_mode=getattr(args, "usb_net_mode", "auto"),
            usb_net_persist=getattr(args, "usb_net_persist", False),
            target_iface=getattr(args, "target_iface", None),
        )
    auth_ctx: AuthContext = resolve_auth_context(
        explicit_password=args.root_password,
        credentials_file=cred_file,
        host=args.openwrt_host,
    )
    steps["auth_context"] = auth_ctx.to_public_metadata()

    if profile["android_root"]:
        steps["provision_android"] = provision_android(
            plan_path=out_dir / "flash_plan.json",
            tools_dir=args.tools_dir,
            openwrt_host=args.openwrt_host,
            auth_context=auth_ctx,
            credentials_file=cred_file,
            isolate_host=not args.no_host_isolate,
            return_to_openwrt=not args.stay_android,
            serial=args.adb_serial,
        )

    expected_os = "auto"
    if profile["openwrt"] and (not profile["android_root"] or not args.stay_android):
        expected_os = "openwrt"
    elif profile["android_root"]:
        expected_os = "android"

    steps["verify"] = verify_environment(
        openwrt_host=args.openwrt_host,
        auth_context=auth_ctx,
        credentials_file=cred_file,
        profile_id=args.profile,
        expected_active_os=expected_os,
        tools_dir=args.tools_dir,
        check_openclash=args.openclash,
        serial=args.adb_serial,
        out_path=work_dir / "final_verify_report.json",
    )
    write_json(work_dir / "auto_execution_report.json", steps)
    return steps


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="kit.py", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_pre = sub.add_parser("preflight", help="Check host tools, Python deps, ADB pubkey, and routes")
    p_pre.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    p_pre.add_argument("--adb-pubkey", type=Path)
    p_pre.add_argument("--operation", default="all")
    p_pre.add_argument("--profile", choices=list(PROFILES))
    p_pre.add_argument("--strict", action="store_true", help="Exit non-zero if required modules or tools are missing")

    p_fetch = sub.add_parser("fetch-assets", help="Download and SHA-256 verify selectable Release packs")
    p_fetch.add_argument("--no-openclash", action="store_true")
    p_fetch.add_argument("--host-platform", default="auto", help="auto|win64|linux-x64|linux-arm64|macos|android-arm64|all|none")
    p_fetch.add_argument("--profile", default="all", choices=sorted(PROFILE_PACK_MAP))
    p_fetch.add_argument("--packs", nargs="+", help="Explicit pack keys to fetch")
    p_fetch.add_argument("--list-packs", action="store_true")
    p_fetch.add_argument("--interactive", action="store_true")
    p_fetch.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    p_fetch.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    p_fetch.add_argument("--local-release-dir", type=Path)

    p_bak = sub.add_parser("backup", help="Perform read-only full BROM dump and verify SHA-256 + XML")
    p_bak.add_argument("--output-dir", type=Path, required=True)
    p_bak.add_argument("--verify-only", action="store_true")
    p_bak.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    p_bak.add_argument("--webui-password")
    p_bak.add_argument("--webui-host", default="http://192.168.0.1:8080")
    p_bak.add_argument("--spd-mode", default="auto", choices=["auto", "direct", "sudo", "su", "termux-usb"])
    p_bak.add_argument("--usb-dev")

    p_ins = sub.add_parser("inspect", help="Inspect verified BROM backup and detect board_id / trustos offset")
    p_ins.add_argument("--backup-dir", type=Path, required=True)
    p_ins.add_argument("--out", type=Path)

    p_bld = sub.add_parser("build", help="Build offline pure-Python images and flash_plan.json")
    p_bld.add_argument("--backup-dir", type=Path, required=True)
    p_bld.add_argument("--profile", required=True, choices=list(PROFILES))
    p_bld.add_argument("--out-dir", type=Path, required=True)
    p_bld.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    p_bld.add_argument("--adb-pubkey", type=Path)
    p_bld.add_argument("--usb-mode")

    p_fl = sub.add_parser("flash", help="Dry-run or execute verified flash_plan.json via BROM")
    p_fl.add_argument("--plan", type=Path, required=True)
    p_fl.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    p_fl.add_argument("--webui-password")
    p_fl.add_argument("--webui-host", default="http://192.168.0.1:8080")
    p_fl.add_argument("--spd-mode", default="auto", choices=["auto", "direct", "sudo", "su", "termux-usb"])
    p_fl.add_argument("--usb-dev")
    p_fl.add_argument("--execute", action="store_true")

    p_ow = sub.add_parser("provision-openwrt", help="Provision OpenWrt _b after flashing")
    p_ow.add_argument("--profile", required=True, choices=[k for k, v in PROFILES.items() if v["openwrt"]])
    p_ow.add_argument("--openwrt-host", default="192.168.77.1")
    p_ow.add_argument("--wifi-ssid", default="F50Pro-OpenWrt")
    p_ow.add_argument("--wifi-password")
    p_ow.add_argument("--root-password")
    p_ow.add_argument("--generate-password", action="store_true")
    p_ow.add_argument("--openclash", action="store_true")
    p_ow.add_argument("--no-host-isolate", action="store_true")
    p_ow.add_argument("--no-reboot", action="store_true")
    p_ow.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    p_ow.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    p_ow.add_argument("--out-dir", type=Path)
    p_ow.add_argument("--usb-net-mode", default="auto", choices=["auto", *sorted(VALID_USB_NET_MODES)])
    p_ow.add_argument("--usb-net-persist", action="store_true")
    p_ow.add_argument("--target-iface")

    p_an = sub.add_parser("provision-android", help="Provision Magisk + UFI-TOOLS on Android _a")
    p_an.add_argument("--plan", type=Path, required=True)
    p_an.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    p_an.add_argument("--openwrt-host", default="192.168.77.1")
    p_an.add_argument("--root-password")
    p_an.add_argument("--credentials-file", type=Path)
    p_an.add_argument("--no-host-isolate", action="store_true")
    p_an.add_argument("--stay-android", action="store_true")
    p_an.add_argument("--adb-serial")

    p_vf = sub.add_parser("verify", help="Verify host route isolation and live device services")
    p_vf.add_argument("--openwrt-host", default="192.168.77.1")
    p_vf.add_argument("--root-password")
    p_vf.add_argument("--credentials-file", type=Path)
    p_vf.add_argument("--profile", choices=list(PROFILES))
    p_vf.add_argument("--expected-active-os", default="auto", choices=["auto", "openwrt", "android"])
    p_vf.add_argument("--openclash", action="store_true")
    p_vf.add_argument("--adb-serial")
    p_vf.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    p_vf.add_argument("--out", type=Path)

    p_au = sub.add_parser("auto", help="Full turnkey workflow (safe dry-run unless --execute is passed)")
    p_au.add_argument("--profile", required=True, choices=list(PROFILES))
    p_au.add_argument("--work-dir", type=Path, default=Path("build/device-session"))
    p_au.add_argument("--reuse-backup", action="store_true")
    p_au.add_argument("--host-platform", default="auto")
    p_au.add_argument("--spd-mode", default="auto", choices=["auto", "direct", "sudo", "su", "termux-usb"])
    p_au.add_argument("--usb-dev")
    p_au.add_argument("--adb-serial")
    p_au.add_argument("--webui-password")
    p_au.add_argument("--webui-host", default="http://192.168.0.1:8080")
    p_au.add_argument("--openwrt-host", default="192.168.77.1")
    p_au.add_argument("--wifi-ssid", default="F50Pro-OpenWrt")
    p_au.add_argument("--wifi-password")
    p_au.add_argument("--root-password")
    p_au.add_argument("--generate-password", action="store_true")
    p_au.add_argument("--openclash", action="store_true")
    p_au.add_argument("--adb-pubkey", type=Path)
    p_au.add_argument("--usb-mode")
    p_au.add_argument("--no-host-isolate", action="store_true")
    p_au.add_argument("--stay-android", action="store_true")
    p_au.add_argument("--usb-net-mode", default="auto", choices=["auto", *sorted(VALID_USB_NET_MODES)])
    p_au.add_argument("--usb-net-persist", action="store_true")
    p_au.add_argument("--target-iface")
    p_au.add_argument("--execute", action="store_true")
    p_au.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    p_au.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cmd = args.command
    exit_code = 0
    if cmd == "preflight":
        out = run_preflight(
            tools_dir=args.tools_dir,
            adb_pubkey=args.adb_pubkey,
            operation=args.operation,
            profile=args.profile,
        )
        if args.strict and not out["ready"]:
            exit_code = 1
    elif cmd == "fetch-assets":
        manifest = read_json(MANIFEST_PATH)
        if args.list_packs:
            out = {
                "release_tag": manifest["release_tag"],
                "detected_platform": detect_host_platform(),
                "packs": list_available_packs(manifest),
            }
        else:
            host_plat = args.host_platform
            prof = args.profile
            inc_oc = not args.no_openclash
            if args.interactive:
                host_plat, prof, inc_oc = interactive_select(manifest)
            lrd = _rel(args.local_release_dir) if args.local_release_dir else None
            out = fetch_and_extract(
                include_openclash=inc_oc,
                host_platform=host_plat,
                profile=prof,
                explicit_packs=args.packs,
                cache_dir=args.cache_dir,
                tools_dir=args.tools_dir,
                local_release_dir=lrd,
            )
    elif cmd == "backup":
        odir = _rel(args.output_dir)
        if args.verify_only:
            out = verify_backup_dir(odir)
        else:
            assert_preflight_ready(operation="backup", tools_dir=args.tools_dir)
            out = run_brom_backup(
                odir,
                tools_dir=args.tools_dir,
                webui_password=args.webui_password,
                webui_host=args.webui_host,
                spd_mode=args.spd_mode,
                usb_dev=args.usb_dev,
            )
    elif cmd == "inspect":
        out = inspect_backup_dir(_rel(args.backup_dir), _rel(args.out) if args.out else None)
    elif cmd == "build":
        out = build_profile(
            backup_dir=_rel(args.backup_dir),
            profile_id=args.profile,
            out_dir=_rel(args.out_dir),
            tools_dir=args.tools_dir,
            adb_pubkey_path=args.adb_pubkey,
            usb_mode=args.usb_mode,
        )
    elif cmd == "flash":
        if args.execute:
            assert_preflight_ready(operation="flash", tools_dir=args.tools_dir)
        out = execute_flash(
            _rel(args.plan),
            tools_dir=args.tools_dir,
            webui_password=args.webui_password,
            webui_host=args.webui_host,
            execute=args.execute,
            spd_mode=args.spd_mode,
            usb_dev=args.usb_dev,
        )
    elif cmd == "provision-openwrt":
        assert_preflight_ready(operation="provision-openwrt", tools_dir=args.tools_dir, profile=args.profile)
        out = provision_openwrt(
            profile_id=args.profile,
            openwrt_host=args.openwrt_host,
            wifi_ssid=args.wifi_ssid,
            wifi_password=args.wifi_password,
            root_password=args.root_password,
            generate_password=args.generate_password,
            tools_dir=args.tools_dir,
            cache_dir=args.cache_dir,
            include_openclash=args.openclash,
            isolate_host=not args.no_host_isolate,
            out_dir=_rel(args.out_dir) if args.out_dir else None,
            reboot_after=not args.no_reboot,
            usb_net_mode=args.usb_net_mode,
            usb_net_persist=args.usb_net_persist,
            target_iface=args.target_iface,
        )
    elif cmd == "provision-android":
        plan_path = _rel(args.plan)
        plan_prof = read_json(plan_path).get("profile") if plan_path.is_file() else None
        assert_preflight_ready(operation="provision-android", tools_dir=args.tools_dir, profile=plan_prof)
        cred_p = _rel(args.credentials_file) if args.credentials_file else None
        out = provision_android(
            plan_path=plan_path,
            tools_dir=args.tools_dir,
            openwrt_host=args.openwrt_host,
            root_password=args.root_password,
            credentials_file=cred_p,
            isolate_host=not args.no_host_isolate,
            return_to_openwrt=not args.stay_android,
            serial=args.adb_serial,
        )
    elif cmd == "verify":
        assert_preflight_ready(operation="verify", tools_dir=args.tools_dir, profile=args.profile)
        cred_p = _rel(args.credentials_file) if args.credentials_file else None
        auth_ctx = resolve_auth_context(
            explicit_password=args.root_password,
            credentials_file=cred_p,
            host=args.openwrt_host,
        )
        out = verify_environment(
            openwrt_host=args.openwrt_host,
            auth_context=auth_ctx,
            credentials_file=cred_p,
            profile_id=args.profile,
            expected_active_os=args.expected_active_os,
            tools_dir=args.tools_dir,
            check_openclash=args.openclash,
            serial=args.adb_serial,
            out_path=_rel(args.out) if args.out else None,
        )
        if out.get("overall_status") != "PASS":
            exit_code = 1
    elif cmd == "auto":
        if args.execute:
            assert_preflight_ready(
                operation="auto",
                tools_dir=args.tools_dir,
                profile=args.profile,
                adb_pubkey=args.adb_pubkey,
            )
        out = run_auto(args)
        if "verify" in out and out["verify"].get("overall_status") != "PASS":
            exit_code = 1
    else:
        raise ValueError(f"Unsupported command {cmd}")

    print(json.dumps(out, indent=2, ensure_ascii=False))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
