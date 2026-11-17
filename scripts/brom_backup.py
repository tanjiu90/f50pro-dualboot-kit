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
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable

from common import (
    DEFAULT_TOOLS_DIR,
    REPO_ROOT,
    AuthContext,
    detect_host_platform,
    parse_boot_control,
    resolve_auth_context,
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


class WebUIAuthError(RuntimeError):
    """Raised when stock ZTE WebUI explicitly rejects credentials."""


def _attempt_zte_webui_reboot_once(
    password: str,
    host: str = "http://192.168.0.1:8080",
) -> dict[str, Any] | None:
    """Single non-blocking probe + LOGIN + REBOOT_DEVICE attempt against ZTE stock WebUI."""
    if not password:
        raise ValueError("Explicit --webui-password required when triggering ZTE WebUI reboot")

    def sha_u(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest().upper()

    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def zget(cmd: str) -> dict[str, Any]:
        url = f"{host}/goform/goform_get_cmd_process?isTest=false&multi_data=1&cmd={urllib.parse.quote(cmd)}"
        req = urllib.request.Request(url, headers={"Referer": f"{host}/index.html"})
        with opener.open(req, timeout=2.0) as resp:
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
        with opener.open(req, timeout=2.5) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))

    try:
        info = zget("loginfo,LD,RD,wa_inner_version,cr_version")
    except Exception:
        return None
    if not info or not info.get("LD"):
        return None

    login_hash = sha_u(sha_u(password) + info["LD"])
    login_res = zpost({"isTest": "false", "goformId": "LOGIN", "password": login_hash})
    if str(login_res.get("result")) not in ("0", "4"):
        raise WebUIAuthError(f"WebUI login failed: {login_res}")

    rd = zget("RD")["RD"]
    ad = sha_u(sha_u(info.get("wa_inner_version", "") + info.get("cr_version", "")) + rd)
    reb = zpost({"isTest": "false", "goformId": "REBOOT_DEVICE", "AD": ad})
    return {"method": "webui_reboot_device", "cr_version": info.get("cr_version"), "reboot_response": reb}


def trigger_zte_webui_reboot(
    password: str,
    host: str = "http://192.168.0.1:8080",
    timeout_sec: float = 90.0,
) -> dict[str, Any]:
    """Authenticate against ZTE stock WebUI (goform) and issue REBOOT_DEVICE for --kickto 2 capture."""
    if not password:
        raise ValueError("Explicit --webui-password required when triggering ZTE WebUI reboot")

    deadline = time.monotonic() + max(0.0, timeout_sec)
    while True:
        res = _attempt_zte_webui_reboot_once(password, host=host)
        if res is not None:
            return res
        if time.monotonic() >= deadline:
            break
        time.sleep(1.0)
    raise RuntimeError(f"Stock WebUI unreachable at {host}")


_REAL_WEBUI_REBOOT_FN = trigger_zte_webui_reboot


def _try_openwrt_ssh_reboot_once(
    openwrt_host: str = "192.168.77.1",
    *,
    auth_context: AuthContext | None = None,
) -> dict[str, Any] | None:
    """Trigger reboot via OpenWrt SSH when target is already booted in OpenWrt _b."""
    if not openwrt_host:
        return None
    try:
        with socket.create_connection((openwrt_host, 22), timeout=0.35):
            pass
    except OSError:
        return None

    try:
        from provision_openwrt import connect_ssh, ssh_run

        ctx = auth_context or resolve_auth_context(host=openwrt_host)
        ssh = connect_ssh(openwrt_host, passwords=ctx.candidate_passwords(), timeout=2.5)
        try:
            rc, model_out, _ = ssh_run(ssh, "cat /etc/mu300/model 2>/dev/null", check=False, timeout=3.0)
            if rc != 0 or model_out.strip() != "f50pro":
                return None
            ssh_run(ssh, "sync && reboot", check=False, timeout=3.0)
            return {"method": "openwrt_ssh_reboot", "host": openwrt_host}
        finally:
            ssh.close()
    except Exception:
        return None


def _try_adb_reboot_once(
    *,
    tools_dir: Path = DEFAULT_TOOLS_DIR,
    adb_serial: str | None = None,
) -> dict[str, Any] | None:
    """Trigger reboot via ADB when target is in Android with USB/TCP ADB already authorized."""
    try:
        adb_exe = resolve_tool("adb", tools_dir)
    except FileNotFoundError:
        return None
    if not adb_exe.is_file():
        return None
    base = [str(adb_exe)] + (["-s", adb_serial] if adb_serial else [])
    try:
        st = subprocess.run(
            [*base, "get-state"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=2.0,
            **win_no_window_kwargs(),
        )
        if st.returncode == 0 and st.stdout.strip() == "device":
            subprocess.run(
                [*base, "reboot"],
                capture_output=True,
                text=True,
                timeout=5.0,
                **win_no_window_kwargs(),
            )
            return {"method": "adb_reboot", "serial": adb_serial}
    except Exception:
        return None
    return None


def trigger_online_reboot_once(
    *,
    webui_password: str | None = None,
    webui_host: str = "http://192.168.0.1:8080",
    openwrt_host: str = "192.168.77.1",
    auth_context: AuthContext | None = None,
    adb_serial: str | None = None,
    tools_dir: Path = DEFAULT_TOOLS_DIR,
    webui_trigger_fn: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Attempt one non-blocking software reboot into SPRD4:AutoD via WebUI, OpenWrt SSH, or ADB."""
    if webui_password:
        fn = webui_trigger_fn if webui_trigger_fn is not None else trigger_zte_webui_reboot
        if fn is not _REAL_WEBUI_REBOOT_FN:
            try:
                res = fn(webui_password, host=webui_host)
                return {"method": "webui_reboot_device", **(res or {})}
            except WebUIAuthError:
                raise
            except Exception:
                pass
        else:
            res = _attempt_zte_webui_reboot_once(webui_password, host=webui_host)
            if res is not None:
                return res

    ssh_res = _try_openwrt_ssh_reboot_once(openwrt_host, auth_context=auth_context)
    if ssh_res is not None:
        return ssh_res

    return _try_adb_reboot_once(tools_dir=tools_dir, adb_serial=adb_serial)


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
        "network_downloads": [],
        "device_read_ops": [],
        "device_mutations": [],
        "device_rebooted": False,
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


def _spd_token(val: object) -> str:
    s = str(val)
    if any(ch in s for ch in ('\r', '\n', '"')):
        raise ValueError(f"Unsafe spd_dump token: {s!r}")
    return f'"{s}"'


def _drain_stream_to_queue(
    stream: Any,
    out_queue: queue.Queue[str | None],
    log_handle: Any,
    *,
    banner: str | None = None,
) -> None:
    if banner:
        log_handle.write(banner)
        log_handle.flush()
    for line in stream:
        log_handle.write(line)
        log_handle.flush()
        out_queue.put(line)
    out_queue.put(None)


def _drain_path_to_queue(
    stream: Any,
    out_queue: queue.Queue[str | None],
    log_path: Path,
    *,
    mode: str = "w",
    banner: str | None = None,
) -> None:
    with log_path.open(mode, encoding="utf-8") as lf:
        _drain_stream_to_queue(stream, out_queue, lf, banner=banner)


class SpdSession:
    """Interactive SPRD4:AutoD (FDL2>) session shared across single-session backup and flash."""

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
        popen_factory: Callable[..., Any] | None = None,
    ):
        self.work_dir = work_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)
        run_cwd = cwd or self.work_dir
        run_cwd.mkdir(parents=True, exist_ok=True)
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
            str(self.work_dir),
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

        spawn = popen_factory or subprocess.Popen
        self.proc = spawn(
            cmd,
            cwd=run_cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            **win_no_window_kwargs(),
        )
        actual_log = log_path or (self.work_dir / log_name)
        actual_log.parent.mkdir(parents=True, exist_ok=True)
        self.log = actual_log.open(log_mode, encoding="utf-8")
        self.tail: list[str] = []
        self.handshake_seen = False
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self) -> None:
        assert self.proc.stdout
        _drain_stream_to_queue(self.proc.stdout, self.lines, self.log)

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
            stripped = line.strip()
            buf.append(stripped)
            self.tail = (self.tail + [stripped])[-25:]
            if any(m in line for m in ("BSL_REP_VER:", "save dir is", "Read Part Done")):
                self.handshake_seen = True
            if FATAL_SPD_RE.search(line) and "Waiting" not in line:
                meta = getattr(self, "launch_meta", {})
                raise RuntimeError(f"Fatal spd_dump output: {_explain_libusb_error(stripped, meta)}")
            for m in markers:
                if m in line:
                    return m, buf
        raise TimeoutError(f"Timed out waiting for {markers}; tail={buf[-8:]}")

    def wait_for_handshake(
        self,
        *,
        webui_password: str | None = None,
        webui_host: str = "http://192.168.0.1:8080",
        openwrt_host: str = "192.168.77.1",
        auth_context: AuthContext | None = None,
        adb_serial: str | None = None,
        tools_dir: Path = DEFAULT_TOOLS_DIR,
        reboot_already_triggered: bool = False,
        webui_timeout_sec: float = 90.0,
        handshake_timeout: int = 120,
        webui_trigger_fn: Callable[..., dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        """Wait for SPRD4 FDL2 prompt while triggering online reboot cleanly when at boot_diag."""
        boot_diag_seen = False
        autod_seen = False
        reboot_info: dict[str, Any] | None = {"method": "already_triggered"} if reboot_already_triggered else None
        self.reboot_info: dict[str, Any] | None = None
        reboot_deadline: float | None = None
        last_probe_ts: float | None = None
        deadline = time.monotonic() + max(handshake_timeout, int(webui_timeout_sec) + 45)
        buf: list[str] = []

        while time.monotonic() < deadline:
            try:
                line = self.lines.get(timeout=0.5)
            except queue.Empty:
                if self.proc.poll() is not None:
                    raise RuntimeError(f"spd_dump exited early; tail={buf[-8:]}")
                now = time.monotonic()
                if (
                    boot_diag_seen
                    and not autod_seen
                    and not self.handshake_seen
                    and reboot_info is None
                    and reboot_deadline is not None
                    and now <= reboot_deadline
                    and (last_probe_ts is None or now - last_probe_ts >= 1.5)
                ):
                    last_probe_ts = now
                    reboot_info = trigger_online_reboot_once(
                        webui_password=webui_password,
                        webui_host=webui_host,
                        openwrt_host=openwrt_host,
                        auth_context=auth_context,
                        adb_serial=adb_serial,
                        tools_dir=tools_dir,
                        webui_trigger_fn=webui_trigger_fn,
                    )
                    if reboot_info is not None:
                        self.reboot_info = reboot_info
                continue

            if line is None:
                raise RuntimeError(f"spd_dump exited early; tail={buf[-8:]}")
            stripped = line.strip()
            buf.append(stripped)
            self.tail = (self.tail + [stripped])[-25:]
            if "Waiting for boot_diag" in line:
                boot_diag_seen = True
                if reboot_deadline is None:
                    reboot_deadline = time.monotonic() + max(0.0, webui_timeout_sec)
            if any(m in line for m in ("Waiting for dl_diag", "Try to convert termux transfered usb port fd.")):
                autod_seen = True
            if any(m in line for m in ("BSL_REP_VER:", "save dir is", "Read Part Done")):
                self.handshake_seen = True
            if FATAL_SPD_RE.search(line) and "Waiting" not in line:
                meta = getattr(self, "launch_meta", {})
                raise RuntimeError(f"Fatal spd_dump output: {_explain_libusb_error(stripped, meta)}")
            if "save dir is" in line:
                return reboot_info
        raise TimeoutError(f"Timed out waiting for SPRD4 handshake ('save dir is'); tail={buf[-8:]}")

    def send_line(self, args: list[object]) -> None:
        assert self.proc.stdin
        self.proc.stdin.write(" ".join(_spd_token(a) for a in args) + "\n")
        self.proc.stdin.flush()

    def cmd(self, args: list[object], ok: str, errs: tuple[str, ...] = (), timeout: int = 240) -> str:
        self.send_line(args)
        hit, _ = self.expect_any((ok, *errs), timeout=timeout)
        if hit != ok:
            raise RuntimeError(f"Command {args[0]} hit error marker: {hit}")
        return hit

    def switch_dir(self, new_dir: Path) -> None:
        new_dir.mkdir(parents=True, exist_ok=True)
        self.cmd(["path", str(new_dir)], "save dir is", timeout=30)
        self.work_dir = new_dir

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


def open_sprd4_session(
    spd_dump: Path,
    work_dir: Path,
    *,
    wait_sec: int = 120,
    tools_dir: Path = DEFAULT_TOOLS_DIR,
    spd_mode: str = "auto",
    usb_dev: str | None = None,
    webui_password: str | None = None,
    webui_host: str = "http://192.168.0.1:8080",
    openwrt_host: str = "192.168.77.1",
    auth_context: AuthContext | None = None,
    adb_serial: str | None = None,
    webui_timeout_sec: float = 90.0,
    cwd: Path | None = None,
    log_name: str = "spd_dump_session.log",
    log_path: Path | None = None,
    session_cls: type[SpdSession] = SpdSession,
    webui_trigger_fn: Callable[..., dict[str, Any]] | None = None,
) -> tuple[SpdSession, dict[str, Any] | None]:
    """Connect interactive SPRD4 FDL2 session with multi-transport reboot and pre-handshake race retries."""
    reboot_info: dict[str, Any] | None = None
    last_exc: Exception | None = None
    for attempt in range(1, 5):
        cand = session_cls(
            spd_dump,
            work_dir,
            wait_sec=wait_sec,
            tools_dir=tools_dir,
            spd_mode=spd_mode,
            usb_dev=usb_dev,
            cwd=cwd,
            log_name=log_name,
            log_path=log_path,
            log_mode="w" if attempt == 1 else "a",
        )
        try:
            rb = cand.wait_for_handshake(
                webui_password=webui_password,
                webui_host=webui_host,
                openwrt_host=openwrt_host,
                auth_context=auth_context,
                adb_serial=adb_serial,
                tools_dir=tools_dir,
                reboot_already_triggered=reboot_info is not None,
                webui_timeout_sec=webui_timeout_sec,
                handshake_timeout=wait_sec + 30,
                webui_trigger_fn=webui_trigger_fn,
            )
            if reboot_info is None and rb is not None:
                reboot_info = rb
            return cand, reboot_info
        except WebUIAuthError:
            cand.close(reboot=False)
            raise
        except Exception as exc:
            last_exc = exc
            cand_rb = getattr(cand, "reboot_info", None)
            if reboot_info is None and cand_rb is not None:
                reboot_info = cand_rb
            pre_race = (not cand.handshake_seen) and any(
                tok in "\n".join(cand.tail) or tok in str(exc)
                for tok in ("Connection failed", "libusb_open_device failed")
            )
            cand.close(reboot=False)
            if pre_race and attempt < 4:
                time.sleep(0.4)
                continue
            raise
    raise RuntimeError(f"Failed to connect to F50 Pro SPRD4/BROM port: {last_exc}")


def run_brom_backup_session(
    output_dir: Path,
    flash_run_dir: Path,
    *,
    tools_dir: Path = DEFAULT_TOOLS_DIR,
    wait_sec: int = 120,
    webui_password: str | None = None,
    webui_host: str = "http://192.168.0.1:8080",
    openwrt_host: str = "192.168.77.1",
    auth_context: AuthContext | None = None,
    adb_serial: str | None = None,
    spd_mode: str = "auto",
    usb_dev: str | None = None,
    authorize_device_reboot: bool = False,
) -> tuple[dict[str, Any], SpdSession]:
    """Capture verified full BROM backup and leave SPRD4 FDL2 session open (zero mid-flow reset)."""
    if not authorize_device_reboot:
        raise PermissionError(
            "Live BROM backup enters SPRD4:AutoD (optional WebUI/SSH/ADB reboot) and reads full flash; "
            "pass authorize_device_reboot=True / --authorize-device-reboot."
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    flash_run_dir.mkdir(parents=True, exist_ok=True)
    prefer_var = "termux-usb" if spd_mode == "termux-usb" else ("su" if spd_mode == "su" else None)
    spd_dump = resolve_tool("spd_dump", tools_dir, prefer_variant=prefer_var)

    sess, reboot_info = open_sprd4_session(
        spd_dump,
        output_dir,
        wait_sec=wait_sec,
        tools_dir=tools_dir,
        spd_mode=spd_mode,
        usb_dev=usb_dev,
        webui_password=webui_password,
        webui_host=webui_host,
        openwrt_host=openwrt_host,
        auth_context=auth_context,
        adb_serial=adb_serial,
        cwd=output_dir,
        log_name="spd_dump_session.log",
        log_path=flash_run_dir / "spd_dump_session.log",
    )
    try:
        sess.send_line(["skip_confirm", "1"])
        sess.send_line(["partition_list", str(output_dir / "partition_list.xml")])
        sess.cmd(["path", str(output_dir)], "save dir is", timeout=60)
        # Send 'r all' followed by switching path to flash_run_dir; 'save dir is' confirms r all flushed & closed.
        sess.send_line(["r", "all"])
        sess.cmd(["path", str(flash_run_dir)], "save dir is", timeout=wait_sec + 900)
        sess.work_dir = flash_run_dir
        rep = verify_backup_dir(output_dir, require_complete_table=True)
        rep["spd_launch"] = sess.launch_meta
        rep["device_rebooted"] = reboot_info is not None
        rep["reboot_trigger"] = reboot_info
        rep["device_read_ops"] = ["brom_r_all"]
        rep["device_mutations"] = [
            *([reboot_info["method"]] if reboot_info and reboot_info.get("method") else []),
            "enter_sprd4_autod",
        ]
        rep["network_downloads"] = []
        return rep, sess
    except Exception:
        sess.close(reboot=False)
        raise


def run_brom_backup(
    output_dir: Path,
    *,
    tools_dir: Path = DEFAULT_TOOLS_DIR,
    wait_sec: int = 120,
    webui_password: str | None = None,
    webui_host: str = "http://192.168.0.1:8080",
    openwrt_host: str = "192.168.77.1",
    auth_context: AuthContext | None = None,
    adb_serial: str | None = None,
    spd_mode: str = "auto",
    usb_dev: str | None = None,
    authorize_device_reboot: bool = False,
) -> dict[str, Any]:
    """Execute read-only SPRD4:AutoD dump ('r all reset') and verify every partition."""
    if not authorize_device_reboot:
        raise PermissionError(
            "Live BROM backup enters SPRD4:AutoD (optional WebUI REBOOT_DEVICE) and issues 'reset'; "
            "pass authorize_device_reboot=True / --authorize-device-reboot (or --verify-only for offline check)."
        )
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

    tail: list[str] = []
    rc = -1
    reboot_info: dict[str, Any] | None = None
    for attempt in range(1, 5):
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
        banner = f"\n--- pre-handshake retry attempt {attempt} ---\n" if attempt > 1 else None
        reader_thread = threading.Thread(
            target=_drain_path_to_queue,
            args=(proc.stdout, lines, log_path),
            kwargs={"mode": "w" if attempt == 1 else "a", "banner": banner},
            daemon=True,
        )
        reader_thread.start()
        boot_diag_seen = False
        autod_seen = False
        handshake_seen = False
        reboot_deadline: float | None = None
        last_probe_ts: float | None = None
        deadline = time.monotonic() + wait_sec + 900
        tail = []
        while time.monotonic() < deadline:
            try:
                item = lines.get(timeout=0.5)
            except queue.Empty:
                if proc.poll() is not None:
                    break
                now = time.monotonic()
                if (
                    boot_diag_seen
                    and not autod_seen
                    and not handshake_seen
                    and reboot_info is None
                    and reboot_deadline is not None
                    and now <= reboot_deadline
                    and (last_probe_ts is None or now - last_probe_ts >= 1.5)
                ):
                    last_probe_ts = now
                    reboot_info = trigger_online_reboot_once(
                        webui_password=webui_password,
                        webui_host=webui_host,
                        openwrt_host=openwrt_host,
                        auth_context=auth_context,
                        adb_serial=adb_serial,
                        tools_dir=tools_dir,
                        webui_trigger_fn=trigger_zte_webui_reboot,
                    )
                continue
            if item is None:
                break
            tail.append(item.strip())
            if len(tail) > 25:
                tail.pop(0)
            if "Waiting for dl_diag" in item:
                autod_seen = True
            if any(m in item for m in ("BSL_REP_VER:", "save dir is", "Read Part Done")):
                handshake_seen = True
            if not boot_diag_seen and "Waiting for boot_diag" in item:
                boot_diag_seen = True
                if reboot_deadline is None:
                    reboot_deadline = time.monotonic() + 90.0
            if FATAL_SPD_RE.search(item) and "Waiting" not in item:
                proc.terminate()
                reader_thread.join(timeout=2)
                raise RuntimeError(f"spd_dump fatal error: {_explain_libusb_error(item.strip(), launch_meta)}")

        rc = proc.wait(timeout=30)
        reader_thread.join(timeout=2)
        if rc == 0:
            break
        pre_race = (not handshake_seen) and any(
            tok in "\n".join(tail) for tok in ("Connection failed", "libusb_open_device failed")
        )
        if pre_race and attempt < 4:
            time.sleep(0.15)
            continue
        break

    if rc != 0:
        raise RuntimeError(f"spd_dump backup failed rc={rc} mode={launch_meta['mode']}; tail={tail[-10:]}")
    rep = verify_backup_dir(output_dir, require_complete_table=True)
    rep["spd_launch"] = launch_meta
    rep["device_rebooted"] = True
    rep["reboot_trigger"] = reboot_info
    rep["device_read_ops"] = ["brom_r_all"]
    rep["device_mutations"] = [
        *([reboot_info["method"]] if reboot_info and reboot_info.get("method") else (["webui_reboot_device"] if webui_password else [])),
        "enter_sprd4_autod",
        "spd_reset_device",
    ]
    rep["network_downloads"] = []
    return rep


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--authorize-device-reboot", action="store_true", help="Explicitly authorize entering SPRD4:AutoD and rebooting the device for full BROM dump")
    parser.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    parser.add_argument("--wait-sec", type=int, default=120)
    parser.add_argument("--webui-password", help="Stock WebUI password for automatic REBOOT_DEVICE trigger")
    parser.add_argument("--webui-host", default="http://192.168.0.1:8080")
    parser.add_argument("--openwrt-host", default="192.168.77.1")
    parser.add_argument("--adb-serial")
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
            openwrt_host=args.openwrt_host,
            adb_serial=args.adb_serial,
            spd_mode=args.spd_mode,
            usb_dev=args.usb_dev,
            authorize_device_reboot=args.authorize_device_reboot,
        )
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
