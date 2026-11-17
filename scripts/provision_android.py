"""Android _a provisioning over ADB (Profile 1 direct & Profile 3 OpenWrt-assisted dual-boot)."""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any

from common import (
    ASSETS_DIR,
    DEFAULT_TOOLS_DIR,
    PROFILE_ALLOWED_OPENWRT_STAGE_OPS,
    REPO_ROOT,
    AuthContext,
    read_json,
    resolve_auth_context,
    resolve_tool,
    sha256_bytes,
    win_no_window_kwargs,
    write_json,
)
from host_network import isolate_usb_rndis_adapter
from provision_openwrt import (
    open_remote_fs,
    sftp_put_bytes,
    ssh_run,
    wait_for_openwrt_ssh,
)


def _adb(adb_exe: Path, args: list[str], *, serial: str | None = None, check: bool = True, timeout: float = 60.0) -> str:
    cmd = [str(adb_exe)]
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(args)
    res = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        **win_no_window_kwargs(),
    )
    if check and res.returncode != 0:
        raise RuntimeError(f"adb {' '.join(args)} failed rc={res.returncode}: {res.stdout}{res.stderr}")
    return res.stdout.strip()


def resolve_android_su_bin(adb_exe: Path, *, serial: str | None = None) -> str:
    """Locate Magisk/KernelSU su binary on Android even when omitted from default ADB PATH."""
    probe = (
        "if [ -x /debug_ramdisk/su ]; then echo /debug_ramdisk/su; "
        "elif [ -x /sbin/su ]; then echo /sbin/su; "
        "else command -v su 2>/dev/null || echo su; fi"
    )
    out = _adb(adb_exe, ["shell", probe], serial=serial, check=False, timeout=10.0)
    cand = out.strip().splitlines()[-1].strip() if out.strip() else ""
    return cand if cand else "su"


def _su(adb_exe: Path, script: str, *, serial: str | None = None, check: bool = True, timeout: float = 60.0) -> str:
    su_bin = resolve_android_su_bin(adb_exe, serial=serial)
    return _adb(adb_exe, ["shell", f"{su_bin} -c {shlex.quote(script)}"], serial=serial, check=check, timeout=timeout)


def wait_for_adb_slot_a(adb_exe: Path, *, timeout: int = 150, serial: str | None = None) -> str:
    """Wait for USB or TCP ADB online on slot _a with sys.boot_completed=1."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if serial and ":" in serial:
            subprocess.run(
                [str(adb_exe), "connect", serial],
                capture_output=True,
                text=True,
                timeout=5,
                **win_no_window_kwargs(),
            )
        res = subprocess.run(
            [str(adb_exe), "get-state"] if not serial else [str(adb_exe), "-s", serial, "get-state"],
            capture_output=True,
            text=True,
            timeout=5,
            **win_no_window_kwargs(),
        )
        if res.returncode == 0 and res.stdout.strip() == "device":
            slot = _adb(adb_exe, ["shell", "getprop", "ro.boot.slot_suffix"], serial=serial, check=False)
            booted = _adb(adb_exe, ["shell", "getprop", "sys.boot_completed"], serial=serial, check=False)
            if slot == "_a" and booted == "1":
                uid = _su(adb_exe, "id -u", serial=serial, check=False)
                if uid.strip() == "0":
                    return slot
        time.sleep(2.5)
    raise TimeoutError("Timed out waiting for rooted Android _a over ADB")


def apply_slot_a_from_openwrt(
    plan: dict[str, Any],
    *,
    openwrt_host: str = "192.168.77.1",
    root_password: str | None = None,
    auth_context: AuthContext | None = None,
    credentials_file: Path | None = None,
    isolate_host: bool = True,
) -> dict[str, Any]:
    """For Profile 3: safely write trustos_a + init_boot_a from running OpenWrt _b and boot Android _a."""
    stage = plan.get("android_a_stage")
    if not stage or not stage.get("apply_from_openwrt"):
        raise ValueError("flash_plan.json does not specify android_a_stage apply_from_openwrt")

    ctx = auth_context or resolve_auth_context(
        explicit_password=root_password,
        credentials_file=credentials_file,
        host=openwrt_host,
    )
    ssh = wait_for_openwrt_ssh(ctx.host, passwords=ctx.candidate_passwords(), isolate_host=isolate_host)
    try:
        sftp = open_remote_fs(ssh)
        results: dict[str, Any] = {}
        for part in ("trustos_a", "init_boot_a"):
            if part not in PROFILE_ALLOWED_OPENWRT_STAGE_OPS or part not in stage:
                raise ValueError(f"Disallowed or missing stage partition: {part}")
            spec = stage[part]
            payload = Path(spec["file"]).read_bytes()
            if sha256_bytes(payload) != spec["sha256"]:
                raise ValueError(f"Digest mismatch on local {part} image")
            remote_img = f"/tmp/{part}.new.img"
            sftp_put_bytes(sftp, payload, remote_img, mode=0o644)

            dev = f"/dev/block/by-name/{part}"
            _, cur_sha, _ = ssh_run(ssh, f"head -c {spec['size_bytes']} {dev} | sha256sum | cut -d' ' -f1")
            cur_sha = cur_sha.strip()
            if cur_sha == spec["sha256"]:
                results[part] = {"status": "already_written", "sha256": cur_sha}
                ssh_run(ssh, f"rm -f {remote_img}", check=False)
                continue

            ssh_run(ssh, f"dd if={remote_img} of={dev} bs=65536 conv=fsync && sync", timeout=90)
            _, rb_sha, _ = ssh_run(ssh, f"head -c {spec['size_bytes']} {dev} | sha256sum | cut -d' ' -f1")
            rb_sha = rb_sha.strip()
            ssh_run(ssh, f"rm -f {remote_img}", check=False)
            if rb_sha != spec["sha256"]:
                raise RuntimeError(f"Readback SHA mismatch writing {dev} from OpenWrt: {rb_sha} != {spec['sha256']}")
            results[part] = {"status": "written_verified", "sha256": rb_sha}

        # Switch next boot cleanly to Android _a via mu300-next-boot and reboot
        ssh_run(ssh, "/opt/mu300/bin/mu300-next-boot android && sync && reboot", check=False, timeout=10)
    finally:
        ssh.close()
    return results


def provision_android(
    *,
    plan_path: Path,
    tools_dir: Path = DEFAULT_TOOLS_DIR,
    openwrt_host: str = "192.168.77.1",
    root_password: str | None = None,
    auth_context: AuthContext | None = None,
    credentials_file: Path | None = None,
    isolate_host: bool = True,
    return_to_openwrt: bool = True,
    serial: str | None = None,
) -> dict[str, Any]:
    """Provision Magisk runtime, UFI-TOOLS, 5s return daemon (Profile 3), and verify cold reboot."""
    plan = read_json(plan_path)
    profile_id = plan["profile"]
    out_dir = Path(plan["out_dir"])
    adb_exe = resolve_tool("adb", tools_dir)

    cred_path = credentials_file
    if cred_path is None and (out_dir / "openwrt-credentials.json").is_file():
        cred_path = out_dir / "openwrt-credentials.json"
    ctx = auth_context or resolve_auth_context(
        explicit_password=root_password,
        credentials_file=cred_path,
        host=openwrt_host,
    )

    from_owrt_res = None
    dual_boot = profile_id == "3-dual-full"
    if dual_boot:
        from_owrt_res = apply_slot_a_from_openwrt(
            plan,
            openwrt_host=ctx.host,
            auth_context=ctx,
            isolate_host=isolate_host,
        )
        time.sleep(8)

    wait_for_adb_slot_a(adb_exe, timeout=180, serial=serial)
    # Pause any failsafe timer during active provisioning
    _su(adb_exe, "touch /data/local/tmp/f50pro-keep-android-test", serial=serial)

    try:
        # 1. Stage complete Magisk 10+1 runtime in /data/adb/magisk
        env_dir = out_dir / "stage3" / "magisk-a" / "magisk-env"
        manifest = read_json(env_dir / "manifest.json")
        _su(adb_exe, "mkdir -p /data/adb/magisk /data/adb/service.d && chmod 700 /data/adb", serial=serial)
        for item in manifest["files"]:
            name = item["name"]
            tmp_dst = f"/data/local/tmp/m_{name}"
            _adb(adb_exe, ["push", str(env_dir / name), tmp_dst], serial=serial)
            _su(
                adb_exe,
                f"mv {tmp_dst} /data/adb/magisk/{name} && chmod {item['mode']} /data/adb/magisk/{name}",
                serial=serial,
            )
        _su(adb_exe, "ln -sf /data/adb/magisk/magisk /data/adb/magisk/resetprop", serial=serial)

        # 2. Install Magisk manager & UFI-TOOLS APKs
        pkgs_dir = tools_dir / "android-pkgs"
        _adb(adb_exe, ["install", "-r", str(pkgs_dir / "Magisk-canary-28103.apk")], serial=serial, timeout=120)
        _adb(adb_exe, ["install", "-r", str(pkgs_dir / "UFI-TOOLS.apk")], serial=serial, timeout=120)

        pkg_line = _adb(adb_exe, ["shell", "pm", "list", "packages", "-U", "com.minikano.f50_sms"], serial=serial)
        m = re.search(r"uid:(\d+)", pkg_line)
        if not m:
            raise RuntimeError(f"Could not determine UID for com.minikano.f50_sms: {pkg_line!r}")
        ufi_uid = int(m.group(1))

        # 3. Seed Magisk SQLite root policy for ADB shell (2000) and UFI-TOOLS
        for uid in (2000, ufi_uid):
            _su(
                adb_exe,
                f"/data/adb/magisk/magisk --sqlite "
                f"\"INSERT OR REPLACE INTO policies (uid,policy,until,logging,notification) VALUES ({uid},2,0,1,1);\"",
                serial=serial,
            )

        # 4. Deploy service.d boot automation & daemon
        scr_dir = ASSETS_DIR / "android-scripts"
        s90 = (scr_dir / "90-ufi-tools.sh").read_text(encoding="utf-8").replace("\r\n", "\n")
        daemon_tpl = (scr_dir / "ufi-tools-daemon.sh.tpl").read_text(encoding="utf-8").replace("\r\n", "\n")
        daemon_txt = daemon_tpl.replace("__ENABLE_KEY_SWITCH_DAEMON__", "1" if dual_boot else "0")

        tmp_90 = out_dir / "stage3" / "90-ufi-tools.sh"
        tmp_dm = out_dir / "stage3" / "ufi-tools-daemon.sh"
        tmp_90.write_text(s90, encoding="utf-8", newline="\n")
        tmp_dm.write_text(daemon_txt, encoding="utf-8", newline="\n")

        _adb(adb_exe, ["push", str(tmp_90), "/data/local/tmp/90-ufi-tools.sh"], serial=serial)
        _adb(adb_exe, ["push", str(tmp_dm), "/data/local/tmp/ufi-tools-daemon.sh"], serial=serial)
        _su(
            adb_exe,
            "mv /data/local/tmp/90-ufi-tools.sh /data/adb/service.d/90-ufi-tools.sh && "
            "mv /data/local/tmp/ufi-tools-daemon.sh /data/adb/ufi-tools-daemon.sh && "
            "chmod 755 /data/adb/service.d/90-ufi-tools.sh /data/adb/ufi-tools-daemon.sh",
            serial=serial,
        )

        if dual_boot:
            keys_bin = tools_dir / "openwrt-base" / "mu300-keys"
            live_bc = out_dir / "known-good-b-bcab.bin"
            if not live_bc.is_file():
                live_bc = out_dir / "stage3" / "known-good-b-bcab.bin"
            _adb(adb_exe, ["push", str(keys_bin), "/data/local/tmp/mu300-keys"], serial=serial)
            _adb(adb_exe, ["push", str(scr_dir / "ufi-key-daemon.sh"), "/data/local/tmp/ufi-key-daemon.sh"], serial=serial)
            _adb(adb_exe, ["push", str(scr_dir / "switch-to-openwrt.sh"), "/data/local/tmp/switch-to-openwrt.sh"], serial=serial)
            _adb(adb_exe, ["push", str(live_bc), "/data/local/tmp/known-good-b-bcab.bin"], serial=serial)
            _su(
                adb_exe,
                "mv /data/local/tmp/mu300-keys /data/adb/mu300-keys && "
                "mv /data/local/tmp/ufi-key-daemon.sh /data/adb/ufi-key-daemon.sh && "
                "mv /data/local/tmp/switch-to-openwrt.sh /data/adb/switch-to-openwrt.sh && "
                "mv /data/local/tmp/known-good-b-bcab.bin /data/adb/known-good-b-bcab.bin && "
                "chmod 755 /data/adb/mu300-keys /data/adb/ufi-key-daemon.sh /data/adb/switch-to-openwrt.sh && "
                "chmod 644 /data/adb/known-good-b-bcab.bin && "
                "/system/bin/sh /data/adb/switch-to-openwrt.sh --dry-run",
                serial=serial,
            )

        _su(
            adb_exe,
            "touch /data/adb/f50pro-android-test-complete && rm -f /data/local/tmp/f50pro-keep-android-test",
            serial=serial,
        )

        # 5. Cold reboot verification on Android _a
        _adb(adb_exe, ["reboot"], serial=serial, check=False)
        time.sleep(10)
        wait_for_adb_slot_a(adb_exe, timeout=180, serial=serial)

        ports_ok = False
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            ss_out = _su(adb_exe, "ss -tln", serial=serial, check=False)
            if ":2333 " in ss_out and ":1146 " in ss_out:
                ports_ok = True
                break
            time.sleep(2.5)
        if not ports_ok:
            raise RuntimeError("UFI-TOOLS (:2333) or ttyd (:1146) did not come up after cold reboot")

        usb_cfg = _adb(adb_exe, ["shell", "getprop", "persist.sys.usb.config"], serial=serial)
        returned_to_openwrt = False
        if dual_boot and return_to_openwrt:
            _su(adb_exe, "/system/bin/sh /data/adb/switch-to-openwrt.sh", serial=serial, check=False)
            time.sleep(10)
            ssh_b = wait_for_openwrt_ssh(ctx.host, passwords=ctx.candidate_passwords(), isolate_host=isolate_host)
            ssh_b.close()
            if isolate_host:
                isolate_usb_rndis_adapter()
            returned_to_openwrt = True

        res = {
            "status": "ANDROID_PROVISIONED",
            "profile": profile_id,
            "ufi_uid": ufi_uid,
            "auth_context": ctx.to_public_metadata(),
            "from_openwrt_flash": from_owrt_res,
            "cold_reboot_ports_verified": ports_ok,
            "usb_config": usb_cfg,
            "returned_to_openwrt": returned_to_openwrt,
        }
        write_json(out_dir / "android_provision_report.json", res)
        return res
    except Exception:
        _su(adb_exe, "rm -f /data/local/tmp/f50pro-keep-android-test", serial=serial, check=False)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    parser.add_argument("--openwrt-host", default="192.168.77.1")
    parser.add_argument("--root-password")
    parser.add_argument("--credentials-file", type=Path)
    parser.add_argument("--no-host-isolate", action="store_true")
    parser.add_argument("--stay-android", action="store_true")
    parser.add_argument("--serial")
    args = parser.parse_args()

    p = args.plan if args.plan.is_absolute() else (REPO_ROOT / args.plan)
    res = provision_android(
        plan_path=p,
        tools_dir=args.tools_dir,
        openwrt_host=args.openwrt_host,
        root_password=args.root_password,
        credentials_file=args.credentials_file,
        isolate_host=not args.no_host_isolate,
        return_to_openwrt=not args.stay_android,
        serial=args.serial,
    )
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
