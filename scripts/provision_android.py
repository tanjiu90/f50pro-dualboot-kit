"""Android _a provisioning over ADB (Profile 1 direct & Profile 3 OpenWrt-assisted dual-boot)."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shlex
import string
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
    compute_unit_identity_digest,
    read_json,
    resolve_auth_context,
    resolve_tool,
    sha256_bytes,
    win_no_window_kwargs,
    write_json,
)
from provision_openwrt import (
    open_remote_fs,
    sftp_put_bytes,
    ssh_run,
    verify_openwrt_target_identity,
    verify_target_identity_with_runner,
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


def _verify_openwrt_target_identity(
    ssh,
    plan: dict[str, Any],
    *,
    confirm_weak_identity: bool = False,
) -> dict[str, Any]:
    """Verify the running OpenWrt device matches flash_plan.json device_identity before touching slot _a."""
    identity = plan.get("device_identity")
    if not identity or not isinstance(identity, dict):
        raise RuntimeError("Flash plan missing target device_identity binding; refusing to write slot _a from OpenWrt")

    unit_specs = identity.get("unit_identity_partitions") or {}
    if identity.get("identity_strength") != "strong" or not unit_specs or not identity.get("unit_identity_sha256"):
        if not confirm_weak_identity:
            raise RuntimeError(
                "Target device identity is weak/insufficient; refusing automatic slot _a write from OpenWrt."
            )

    if identity.get("board_id"):
        _, bid_out, _ = ssh_run(
            ssh,
            "cat /proc/driver/board_id 2>/dev/null || sed -n 's/.*zteboot\\.zte_boardid=\\([0-9]*\\).*/\\1/p' /proc/cmdline 2>/dev/null || true",
            check=False,
        )
        live_bid = bid_out.strip()
        if not live_bid or str(live_bid) != str(identity["board_id"]):
            raise RuntimeError(f"Target board_id mismatch or unreadable on OpenWrt: plan={identity['board_id']} vs live={live_bid!r}")

    live_part_records: dict[str, dict[str, Any]] = {}
    for pname, spec in sorted(unit_specs.items()):
        if not re.fullmatch(r"[A-Za-z0-9_]+", pname):
            raise ValueError(f"Unsafe identity partition name: {pname!r}")
        sz = int(spec["size_bytes"])
        dev = f"/dev/block/by-name/{pname}"
        _, sha_out, _ = ssh_run(ssh, f"head -c {sz} {dev} | sha256sum | cut -d' ' -f1")
        digest = sha_out.strip().lower()
        if len(digest) != 64 or digest != str(spec["sha256"]).lower():
            raise RuntimeError(
                f"Target device identity mismatch on OpenWrt '{pname}': connected unit does NOT match flash_plan.json"
            )
        live_part_records[pname] = {"size_bytes": sz, "sha256": digest}

    if unit_specs:
        live_unit = compute_unit_identity_digest(live_part_records)
        if live_unit["unit_identity_sha256"] != identity["unit_identity_sha256"]:
            raise RuntimeError("Target unit_identity_sha256 mismatch on OpenWrt")

    fw = identity.get("firmware_build") or {}
    expected_vb_sha = fw.get("vendor_boot_a_sha256")
    if expected_vb_sha:
        bdir = plan.get("backup_dir")
        vb_file = (Path(bdir) / "vendor_boot_a") if bdir else None
        vb_sz = int(fw["vendor_boot_a_size_bytes"]) if fw.get("vendor_boot_a_size_bytes") else (
            vb_file.stat().st_size if (vb_file and vb_file.is_file()) else 0
        )
        if vb_sz <= 0:
            raise RuntimeError(
                "Unable to verify target vendor_boot_a firmware build digest: missing vendor_boot_a size in plan/backup_dir"
            )
        _, vb_out, _ = ssh_run(ssh, f"head -c {vb_sz} /dev/block/by-name/vendor_boot_a | sha256sum | cut -d' ' -f1")
        if vb_out.strip().lower() != str(expected_vb_sha).lower():
            raise RuntimeError("Target vendor_boot_a firmware build digest mismatch on OpenWrt")

    return {
        "verified": True,
        "verified_sources": sorted(live_part_records.keys()),
        "unit_identity_sha256": identity.get("unit_identity_sha256"),
    }


def apply_slot_a_from_openwrt(
    plan: dict[str, Any],
    *,
    openwrt_host: str = "192.168.77.1",
    root_password: str | None = None,
    auth_context: AuthContext | None = None,
    credentials_file: Path | None = None,
    isolate_host: bool = True,
    confirm_weak_identity: bool = False,
    snapshot_path: Path | None = None,
    target_iface: str | None = None,
) -> dict[str, Any]:
    """For Profile 3: verify backup, target identity & stock digests, stage both images, then write trustos_a + init_boot_a."""
    stage = plan.get("android_a_stage")
    if not stage or not stage.get("apply_from_openwrt"):
        raise ValueError("flash_plan.json does not specify android_a_stage apply_from_openwrt")

    # Verify complete backup integrity & checksum manifest before touching OpenWrt or slot _a.
    bdir_raw = plan.get("backup_dir")
    expected_sums_sha = plan.get("backup_sha256sums_sha256")
    if not bdir_raw or not expected_sums_sha:
        raise ValueError(
            "Flash plan missing backup_dir or backup_sha256sums_sha256; verify backup (creating SHA256SUMS.txt) and rebuild flash_plan.json before staging slot _a."
        )
    bdir = Path(bdir_raw)
    sums_path = bdir / "SHA256SUMS.txt"
    from brom_backup import verify_backup_dir
    from common import sha256_file

    verify_backup_dir(
        bdir,
        require_complete_table=True,
        require_existing_manifest=True,
    )
    if sha256_file(sums_path) != expected_sums_sha:
        raise ValueError("Backup SHA256SUMS.txt digest changed after flash_plan.json was built")

    # Phase 0 (offline pre-check): validate BOTH non-empty local artifacts before touching SSH or any device block.
    staged_payloads: dict[str, tuple[dict[str, Any], bytes]] = {}
    for part in ("trustos_a", "init_boot_a"):
        if part not in PROFILE_ALLOWED_OPENWRT_STAGE_OPS or part not in stage:
            raise ValueError(f"Disallowed or missing stage partition: {part}")
        spec = stage[part]
        payload = Path(spec["file"]).read_bytes()
        if len(payload) == 0:
            raise ValueError(f"Local staged {part} image is empty (0 bytes)")
        if len(payload) != int(spec["size_bytes"]):
            raise ValueError(f"Size mismatch on local {part} image: {len(payload)} != {spec['size_bytes']}")
        if sha256_bytes(payload) != spec["sha256"]:
            raise ValueError(f"Digest mismatch on local {part} image")
        staged_payloads[part] = (spec, payload)

    ctx = auth_context or resolve_auth_context(
        explicit_password=root_password,
        credentials_file=credentials_file,
        host=openwrt_host,
    )
    ssh = wait_for_openwrt_ssh(
        ctx.host,
        passwords=ctx.candidate_passwords(),
        isolate_host=isolate_host,
        target_iface=target_iface,
        snapshot_path=snapshot_path,
        expected_plan=plan,
        confirm_weak_identity=confirm_weak_identity,
    )
    try:
        # Phase 1: verify live hardware identity + target capacities + stock digests for BOTH partitions BEFORE any write.
        _verify_openwrt_target_identity(ssh, plan, confirm_weak_identity=confirm_weak_identity)

        results: dict[str, Any] = {}
        to_write: list[tuple[str, dict[str, Any], bytes]] = []
        for part in ("trustos_a", "init_boot_a"):
            spec, payload = staged_payloads[part]
            dev = f"/dev/block/by-name/{part}"

            _, cap_out, _ = ssh_run(
                ssh,
                f"blockdev --getsize64 {dev} 2>/dev/null || "
                f"(r=$(readlink -f {dev}); cat \"/sys/class/block/${{r##*/}}/size\" 2>/dev/null | awk '{{print $1*512}}')",
            )
            cap_str = cap_out.strip().splitlines()[-1].strip() if cap_out.strip() else ""
            if not cap_str.isdigit():
                raise RuntimeError(f"Unable to determine live block device capacity for {dev}: {cap_out!r}")
            live_cap = int(cap_str)
            if len(payload) > live_cap:
                raise ValueError(f"Staged {part} ({len(payload)} B) exceeds live block device capacity ({live_cap} B)")

            _, cur_sha, _ = ssh_run(ssh, f"head -c {spec['size_bytes']} {dev} | sha256sum | cut -d' ' -f1")
            cur_sha = cur_sha.strip().lower()
            if cur_sha == str(spec["sha256"]).lower():
                results[part] = {"status": "already_written", "sha256": cur_sha}
                continue

            exp_stock_sha = str(spec.get("expected_stock_sha256") or "").strip().lower()
            if not exp_stock_sha:
                raise ValueError(f"Plan missing mandatory expected_stock_sha256 for {part}")
            stock_len = int(spec.get("expected_stock_first_bytes") or spec["size_bytes"])
            if stock_len == int(spec["size_bytes"]):
                stock_cur_sha = cur_sha
            else:
                _, stock_out, _ = ssh_run(ssh, f"head -c {stock_len} {dev} | sha256sum | cut -d' ' -f1")
                stock_cur_sha = stock_out.strip().lower()
            if stock_cur_sha != exp_stock_sha:
                raise RuntimeError(
                    f"Target {dev} stock SHA-256 mismatch before write: live={stock_cur_sha} != expected_stock={exp_stock_sha}"
                )
            to_write.append((part, spec, payload))

        # Phase 2: stage & verify ALL remote /tmp images BEFORE issuing any dd to slot _a.
        staged_remote: list[tuple[str, dict[str, Any], str]] = []
        sftp = open_remote_fs(ssh) if to_write else None
        try:
            for part, spec, payload in to_write:
                remote_img = f"/tmp/{part}.new.img"
                sftp_put_bytes(sftp, payload, remote_img, mode=0o644)
                _, up_sha, _ = ssh_run(ssh, f"sha256sum {remote_img} | cut -d' ' -f1")
                if up_sha.strip().lower() != str(spec["sha256"]).lower():
                    raise RuntimeError(
                        f"Remote staged upload SHA mismatch for {remote_img}: {up_sha.strip()} != {spec['sha256']}"
                    )
                staged_remote.append((part, spec, remote_img))

            # Phase 3: write & readback-verify only after every precheck & upload succeeded.
            for part, spec, remote_img in staged_remote:
                dev = f"/dev/block/by-name/{part}"
                ssh_run(ssh, f"dd if={remote_img} of={dev} bs=65536 conv=fsync && sync", timeout=90)
                _, rb_sha, _ = ssh_run(ssh, f"head -c {spec['size_bytes']} {dev} | sha256sum | cut -d' ' -f1")
                rb_sha = rb_sha.strip().lower()
                if rb_sha != str(spec["sha256"]).lower():
                    raise RuntimeError(f"Readback SHA mismatch writing {dev} from OpenWrt: {rb_sha} != {spec['sha256']}")
                results[part] = {"status": "written_verified", "sha256": rb_sha}
        finally:
            if to_write:
                rm_targets = " ".join(f"/tmp/{p}.new.img" for p, _, _ in to_write)
                ssh_run(ssh, f"rm -f {rm_targets}", check=False)

        # Switch next boot cleanly to Android _a; fail loudly if mu300-next-boot fails before rebooting.
        ssh_run(ssh, "/opt/mu300/bin/mu300-next-boot android && sync", check=True, timeout=20)
        ssh_run(ssh, "reboot", check=False, timeout=10)
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
    target_iface: str | None = None,
    confirm_weak_identity: bool = False,
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
    snap_path = out_dir / "host_network_snapshot.json"
    if dual_boot:
        from_owrt_res = apply_slot_a_from_openwrt(
            plan,
            openwrt_host=ctx.host,
            auth_context=ctx,
            isolate_host=isolate_host,
            confirm_weak_identity=confirm_weak_identity,
            snapshot_path=snap_path,
            target_iface=target_iface,
        )
        time.sleep(8)

    wait_for_adb_slot_a(adb_exe, timeout=180, serial=serial)
    if serial is None:
        # Pin the exact ADB serial immediately so subsequent commands cannot drift to a second device plugged in mid-run.
        detected_ser = _adb(adb_exe, ["get-serialno"], check=False).strip()
        if detected_ser and detected_ser != "unknown" and "\n" not in detected_ser:
            serial = detected_ser
    # Verify per-unit hardware identity over ADB root BEFORE pushing APKs, scripts, or known-good-b-bcab.bin!
    verify_target_identity_with_runner(
        lambda cmd: _su(adb_exe, cmd, serial=serial, check=False),
        plan,
        confirm_weak_identity=confirm_weak_identity,
        context_label="Android ADB",
    )
    # Pause any failsafe timer during active provisioning AND clear any stale completion marker from an
    # earlier run so the upcoming cold boot MUST pass.
    _su(
        adb_exe,
        "touch /data/local/tmp/f50pro-keep-android-test && rm -f /data/adb/f50pro-android-test-complete",
        serial=serial,
    )
    pause_marker_active = True
    switched_to_openwrt = False
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
        m = re.search(r"^package:com\.minikano\.f50_sms\s+uid:(\d+)\s*$", pkg_line, re.M)
        if not m:
            raise RuntimeError(f"Could not determine exact UID for com.minikano.f50_sms: {pkg_line!r}")
        ufi_uid = int(m.group(1))

        # 3. Seed Magisk SQLite root policy for ADB shell (2000) and UFI-TOOLS
        for uid in (2000, ufi_uid):
            _su(
                adb_exe,
                f"/data/adb/magisk/magisk --sqlite "
                f"\"INSERT OR REPLACE INTO policies (uid,policy,until,logging,notification) VALUES ({uid},2,0,1,1);\"",
                serial=serial,
            )

        # 4. Deploy service.d boot automation, daemon, and hardened zero-backdoor ttyd login script
        scr_dir = ASSETS_DIR / "android-scripts"
        s90 = (scr_dir / "90-ufi-tools.sh").read_text(encoding="utf-8").replace("\r\n", "\n")
        daemon_tpl = (scr_dir / "ufi-tools-daemon.sh.tpl").read_text(encoding="utf-8").replace("\r\n", "\n")
        daemon_txt = daemon_tpl.replace("__ENABLE_KEY_SWITCH_DAEMON__", "1" if dual_boot else "0")
        ttyd_login_txt = (scr_dir / "ufi-ttyd-login.sh").read_text(encoding="utf-8").replace("\r\n", "\n")

        # Generate per-device random ttyd fallback password (eliminating APK hardcoded BACKUP_PASS)
        ttyd_cred_path = out_dir / "android-ttyd-credentials.json"
        if ttyd_cred_path.is_file():
            ttyd_pw = str(read_json(ttyd_cred_path).get("password") or "")
        else:
            ttyd_pw = ""
        if not ttyd_pw:
            alphabet = string.ascii_letters + string.digits
            ttyd_pw = "".join(secrets.choice(alphabet) for _ in range(16))
            write_json(
                ttyd_cred_path,
                {
                    "service": "ufi-tools-ttyd",
                    "port": 1146,
                    "password": ttyd_pw,
                    "note": "Per-device fallback password when UFI-TOOLS app login_token is unset",
                },
            )
        ttyd_pw_sha256 = hashlib.sha256(ttyd_pw.encode("utf-8")).hexdigest()

        tmp_90 = out_dir / "stage3" / "90-ufi-tools.sh"
        tmp_dm = out_dir / "stage3" / "ufi-tools-daemon.sh"
        tmp_login = out_dir / "stage3" / "ufi-ttyd-login.sh"
        tmp_hash = out_dir / "stage3" / "ufi-ttyd.sha256"
        tmp_90.write_text(s90, encoding="utf-8", newline="\n")
        tmp_dm.write_text(daemon_txt, encoding="utf-8", newline="\n")
        tmp_login.write_text(ttyd_login_txt, encoding="utf-8", newline="\n")
        tmp_hash.write_text(ttyd_pw_sha256 + "\n", encoding="utf-8", newline="\n")

        _adb(adb_exe, ["push", str(tmp_90), "/data/local/tmp/90-ufi-tools.sh"], serial=serial)
        _adb(adb_exe, ["push", str(tmp_dm), "/data/local/tmp/ufi-tools-daemon.sh"], serial=serial)
        _adb(adb_exe, ["push", str(tmp_login), "/data/local/tmp/ufi-ttyd-login.sh"], serial=serial)
        _adb(adb_exe, ["push", str(tmp_hash), "/data/local/tmp/ufi-ttyd.sha256"], serial=serial)
        _su(
            adb_exe,
            "mv /data/local/tmp/90-ufi-tools.sh /data/adb/service.d/90-ufi-tools.sh && "
            "mv /data/local/tmp/ufi-tools-daemon.sh /data/adb/ufi-tools-daemon.sh && "
            "mv /data/local/tmp/ufi-ttyd-login.sh /data/adb/ufi-ttyd-login.sh && "
            "mv /data/local/tmp/ufi-ttyd.sha256 /data/adb/ufi-ttyd.sha256 && "
            "chmod 755 /data/adb/service.d/90-ufi-tools.sh /data/adb/ufi-tools-daemon.sh && "
            "chmod 700 /data/adb/ufi-ttyd-login.sh && "
            "chmod 600 /data/adb/ufi-ttyd.sha256",
            serial=serial,
        )

        if dual_boot:
            keys_bin = tools_dir / "openwrt-base" / "mu300-keys"
            live_bc = out_dir / "known-good-b-bcab.bin"
            if not live_bc.is_file():
                live_bc = out_dir / "stage3" / "known-good-b-bcab.bin"
            # Normalize CRLF -> LF before pushing shell scripts to Android /system/bin/sh.
            tmp_key_dm = out_dir / "stage3" / "ufi-key-daemon.sh"
            tmp_sw = out_dir / "stage3" / "switch-to-openwrt.sh"
            tmp_key_dm.write_text(
                (scr_dir / "ufi-key-daemon.sh").read_text(encoding="utf-8").replace("\r\n", "\n"),
                encoding="utf-8",
                newline="\n",
            )
            tmp_sw.write_text(
                (scr_dir / "switch-to-openwrt.sh").read_text(encoding="utf-8").replace("\r\n", "\n"),
                encoding="utf-8",
                newline="\n",
            )
            _adb(adb_exe, ["push", str(keys_bin), "/data/local/tmp/mu300-keys"], serial=serial)
            _adb(adb_exe, ["push", str(tmp_key_dm), "/data/local/tmp/ufi-key-daemon.sh"], serial=serial)
            _adb(adb_exe, ["push", str(tmp_sw), "/data/local/tmp/switch-to-openwrt.sh"], serial=serial)
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

        # Keep 480s auto-rollback ARMED across the cold reboot by removing only the temporary pause marker;
        # NEVER write f50pro-android-test-complete until AFTER verified cold-boot ADB, root, and hardened services pass!
        _su(adb_exe, "rm -f /data/local/tmp/f50pro-keep-android-test", serial=serial)
        pause_marker_active = False

        # 5. Cold reboot verification on Android _a (require two valid, distinct RFC-4122 UUID boot_ids)
        uuid_re = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            re.I,
        )
        pre_boot_id = _adb(adb_exe, ["shell", "cat", "/proc/sys/kernel/random/boot_id"], serial=serial, check=False).strip()
        _adb(adb_exe, ["reboot"], serial=serial, check=True)
        time.sleep(10)
        wait_for_adb_slot_a(adb_exe, timeout=180, serial=serial)
        verify_target_identity_with_runner(
            lambda cmd: _su(adb_exe, cmd, serial=serial, check=False),
            plan,
            confirm_weak_identity=confirm_weak_identity,
            context_label="Android ADB post-reboot",
        )
        post_boot_id = _adb(adb_exe, ["shell", "cat", "/proc/sys/kernel/random/boot_id"], serial=serial, check=False).strip()
        if (
            not uuid_re.match(pre_boot_id)
            or not uuid_re.match(post_boot_id)
            or pre_boot_id.lower() == post_boot_id.lower()
        ):
            raise RuntimeError(
                f"Android cold reboot verification failed: invalid or unchanged /proc/sys/kernel/random/boot_id "
                f"(pre={pre_boot_id!r}, post={post_boot_id!r})"
            )

        # Match ONLY actual ttyd executable lines in `ps -ef` bound to a safe non-cellular interface AND exact login script.
        hardened_ttyd_ps_re = re.compile(
            r"^\S+\s+(?P<pid>\d+)\s+\d+\s+\d+"
            r"(?:\s+(?:\d{2}:\d{2}(?::\d{2})?|[A-Z][a-z]{2}\d{2}|\d{4}-\d{2}-\d{2})"
            r"\s+(?:\?|tty\S*|pts/\S*|console)"
            r"\s+(?:\d+-)?\d{2}:\d{2}:\d{2})?"
            r"\s+(?:[A-Za-z0-9_./-]+/)?ttyd\s+--writable\s+--port\s+1146"
            r"\s+--interface\s+(?P<iface>br0|wlan0|ap0|rndis0|usb0|ncm0|lo|127\.0\.0\.1)"
            r"\s+/data/adb/ufi-ttyd-login\.sh\s*$"
        )
        any_ttyd_exec_re = re.compile(
            r"^\S+\s+(?P<pid>\d+)\s+\d+\s+\d+"
            r"(?:\s+(?:\d{2}:\d{2}(?::\d{2})?|[A-Z][a-z]{2}\d{2}|\d{4}-\d{2}-\d{2})"
            r"\s+(?:\?|tty\S*|pts/\S*|console)"
            r"\s+(?:\d+-)?\d{2}:\d{2}:\d{2})?"
            r"\s+(?:[A-Za-z0-9_./-]+/)?ttyd(?:\s|$)"
        )

        ports_ok = False
        hardened_ttyd_ok = False
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            ss_out = _su(adb_exe, "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null", serial=serial, check=False)
            lines_1146 = [ln for ln in ss_out.splitlines() if re.search(r":1146(?:\s|$)", ln)]
            if ":2333 " in ss_out and lines_1146:
                # Reject ANY wildcard/unbound :1146 listener (0.0.0.0:1146, [::]:1146, :::1146, *:1146)
                wildcard_1146 = any(re.search(r"(?:^|\s)(?:0\.0\.0\.0|\[::\]|::|\*):1146(?:\s|$)", ln) for ln in lines_1146)
                per_line_pids: list[set[str]] = []
                for ln in lines_1146:
                    pids_ln = set(re.findall(r"pid=(\d+)", ln))
                    if not pids_ln:
                        pids_ln = set(re.findall(r"(?:^|\s)(\d+)/[^\s/]+\s*$", ln))
                    per_line_pids.append(pids_ln)
                all_lines_attributed = bool(per_line_pids) and all(bool(p) for p in per_line_pids)
                listener_pids = {pid for s in per_line_pids for pid in s}
                ttyd_ps = _su(adb_exe, "ps -ef 2>/dev/null | grep '[t]tyd' || true", serial=serial, check=False)
                ps_lines = [ln.strip() for ln in ttyd_ps.splitlines() if ln.strip()]
                # Require EVERY :1146 listener line to carry an attributed PID, EVERY listener PID to match a
                # hardened ttyd executable bound to a safe non-cellular interface + exact login script, AND EVERY
                # running ttyd executable in ps to satisfy the same hardened signature.
                port_ttyd_lines = [ln for ln in ps_lines if any_ttyd_exec_re.match(ln)]
                hardened_pids = {
                    m.group("pid")
                    for ln in port_ttyd_lines
                    for m in (hardened_ttyd_ps_re.match(ln),)
                    if m is not None
                }
                pid_matched_ok = all_lines_attributed and bool(listener_pids) and listener_pids.issubset(hardened_pids)
                all_ttyd_hardened = bool(port_ttyd_lines) and all(bool(hardened_ttyd_ps_re.match(ln)) for ln in port_ttyd_lines)
                if not wildcard_1146 and all_ttyd_hardened and pid_matched_ok:
                    ports_ok = True
                    hardened_ttyd_ok = True
                    break
            time.sleep(2.5)
        if not ports_ok or not hardened_ttyd_ok:
            raise RuntimeError(
                "UFI-TOOLS (:2333) or hardened bound ttyd (:1146 with /data/adb/ufi-ttyd-login.sh and --interface) did not come up after cold reboot"
            )

        # Disarm the 480s failsafe rollback ONLY after verified cold-boot root + hardened services pass.
        rollback_token = ""
        stage_info = plan.get("android_a_stage")
        if isinstance(stage_info, dict):
            rollback_token = str(
                stage_info.get("rollback_token")
                or (stage_info.get("init_boot_a") or {}).get("meta", {}).get("rollback_token")
                or ""
            ).strip()
        if rollback_token:
            # Record disarmed token locally BEFORE writing the device marker so future rebuilds NEVER reuse a disarmed token.
            disarmed_p = out_dir / ".rollback_token_disarmed"
            existing_toks = (
                {ln.strip() for ln in disarmed_p.read_text(encoding="utf-8").splitlines() if ln.strip()}
                if disarmed_p.is_file()
                else set()
            )
            existing_toks.add(rollback_token)
            disarmed_p.write_text("\n".join(sorted(existing_toks)) + "\n", encoding="utf-8")
            _su(
                adb_exe,
                f"printf '%s\\n' {shlex.quote(rollback_token)} > /data/adb/f50pro-android-test-complete",
                serial=serial,
            )
        else:
            _su(adb_exe, "touch /data/adb/f50pro-android-test-complete", serial=serial)

        usb_cfg = _adb(adb_exe, ["shell", "getprop", "persist.sys.usb.config"], serial=serial)
        returned_to_openwrt = False
        if dual_boot and return_to_openwrt:
            _su(adb_exe, "/system/bin/sh /data/adb/switch-to-openwrt.sh", serial=serial, check=False)
            switched_to_openwrt = True
            time.sleep(10)
            ssh_b = wait_for_openwrt_ssh(
                ctx.host,
                passwords=ctx.candidate_passwords(),
                isolate_host=isolate_host,
                target_iface=target_iface,
                snapshot_path=snap_path,
                expected_plan=plan,
                confirm_weak_identity=confirm_weak_identity,
            )
            try:
                verify_openwrt_target_identity(ssh_b, plan, confirm_weak_identity=confirm_weak_identity)
            finally:
                ssh_b.close()
            returned_to_openwrt = True

        res = {
            "status": "ANDROID_PROVISIONED",
            "profile": profile_id,
            "ufi_uid": ufi_uid,
            "ttyd_credentials_file": str(ttyd_cred_path),
            "hardened_ttyd_verified": hardened_ttyd_ok,
            "auth_context": ctx.to_public_metadata(),
            "from_openwrt_flash": from_owrt_res,
            "cold_reboot_ports_verified": ports_ok,
            "usb_config": usb_cfg,
            "returned_to_openwrt": returned_to_openwrt,
        }
        write_json(out_dir / "android_provision_report.json", res)
        return res
    except Exception:
        if pause_marker_active and not switched_to_openwrt:
            try:
                _su(adb_exe, "rm -f /data/local/tmp/f50pro-keep-android-test", serial=serial, check=False)
            except Exception:
                pass
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
    parser.add_argument("--target-iface")
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
        target_iface=args.target_iface,
    )
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
