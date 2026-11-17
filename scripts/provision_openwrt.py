"""OpenWrt provisioning over SSH: 2 GiB rootfs grow, board_id=6, capacity UI, LEDs, 5s button, optional OpenClash."""
from __future__ import annotations

import argparse
import base64
import io
import json
import posixpath
import re
import secrets
import string
import subprocess
import tarfile
import time
from pathlib import Path
from typing import Any

from common import (
    ASSETS_DIR,
    DEFAULT_CACHE_DIR,
    DEFAULT_TOOLS_DIR,
    PROFILES,
    REPO_ROOT,
    detect_host_platform,
    parse_boot_control,
    read_json,
    sha256_bytes,
    win_no_window_kwargs,
    write_json,
)
from host_network import (
    bind_inbox_rndis_driver,
    clear_negative_usbflags_rndis,
    isolate_usb_rndis_adapter,
)

BOARD6_BEFORE_SHA256 = "f012519ac05c10e1f5ccdaa3dddb86eafe78c2ae11fc0ddb37a9eb8ae79c5b47"
BOARD6_AFTER_SHA256 = "d283d5a7388d05cae7f2645e6bf9a9f5a7ddee5d09c12a5e69d6f5c56663af47"


def _paramiko():
    import paramiko  # type: ignore

    return paramiko


def connect_ssh(
    host: str = "192.168.77.1",
    *,
    username: str = "root",
    passwords: tuple[str, ...] = ("", "root"),
    timeout: float = 8.0,
):
    """Connect to OpenWrt dropbear via Paramiko, handling both empty and configured passwords."""
    pm = _paramiko()
    last_exc: Exception | None = None
    seen: list[str] = []
    for pw in passwords:
        if pw not in seen:
            seen.append(pw)
    for pw in seen:
        client = pm.SSHClient()
        client.set_missing_host_key_policy(pm.AutoAddPolicy())
        try:
            client.connect(
                host,
                port=22,
                username=username,
                password=pw,
                timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            return client
        except Exception as exc:
            last_exc = exc
            if pw == "":
                # Paramiko may need auth_none on Dropbear accounts without a password.
                try:
                    transport = client.get_transport()
                    if transport is not None and transport.is_active():
                        transport.auth_none(username)
                        return client
                except Exception as exc2:
                    last_exc = exc2
            client.close()
    raise RuntimeError(f"Unable to connect SSH to {username}@{host}: {last_exc}")


def ssh_run(ssh, cmd: str, *, check: bool = True, timeout: float = 60.0) -> tuple[int, str, str]:
    """Execute a shell command over SSH and capture (exit_code, stdout, stderr)."""
    _, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    rc = stdout.channel.recv_exit_status()
    if check and rc != 0:
        raise RuntimeError(f"SSH command failed rc={rc}: {cmd}\nstdout={out}\nstderr={err}")
    return rc, out, err


def sftp_put_bytes(sftp, data: bytes, remote_path: str, *, mode: int = 0o644) -> None:
    """Upload raw bytes atomically over SFTP and apply UNIX file mode."""
    parent = posixpath.dirname(remote_path)
    tmp = f"{parent}/.{posixpath.basename(remote_path)}.tmp"
    with sftp.open(tmp, "wb") as f:
        f.write(data)
    sftp.chmod(tmp, mode)
    sftp.posix_rename(tmp, remote_path)


def sftp_get_bytes(sftp, remote_path: str) -> bytes:
    """Download a remote file cleanly over SFTP."""
    with sftp.open(remote_path, "rb") as f:
        return f.read()


class _SshBase64WriteFile:
    """Writable file-like buffer that streams base64 over SSH stdin to BusyBox base64 -d."""

    def __init__(self, ssh, remote_path: str) -> None:
        self._ssh = ssh
        self._remote_path = remote_path
        self._buf = io.BytesIO()
        self.closed = False

    def write(self, data: bytes | bytearray | memoryview) -> int:
        return self._buf.write(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        raw = self._buf.getvalue()
        parent = posixpath.dirname(self._remote_path) or "/"
        q_parent = _shq(parent)
        q_path = _shq(self._remote_path)
        if not raw:
            ssh_run(self._ssh, f"mkdir -p {q_parent} && : > {q_path}")
            return
        timeout = max(120.0, len(raw) / 50000.0 + 30.0)
        stdin, stdout, stderr = self._ssh.exec_command(
            f"mkdir -p {q_parent} && base64 -d > {q_path}",
            timeout=timeout,
        )
        b64 = base64.b64encode(raw).decode("ascii")
        # Stream wrapped base64 chunks via stdin so multi-MB uploads never hit ARG_MAX or line limits.
        for off in range(0, len(b64), 49152):
            stdin.write(b64[off : off + 49152] + "\n")
        stdin.flush()
        if getattr(stdin, "channel", None) is not None:
            stdin.channel.shutdown_write()
        raw_out = stdout.read()
        raw_err = stderr.read()
        out = raw_out.decode("utf-8", "replace") if isinstance(raw_out, (bytes, bytearray)) else str(raw_out)
        err = raw_err.decode("utf-8", "replace") if isinstance(raw_err, (bytes, bytearray)) else str(raw_err)
        rc = stdout.channel.recv_exit_status()
        if rc != 0:
            raise RuntimeError(
                f"SSH base64 upload failed rc={rc} path={self._remote_path}: stdout={out} stderr={err}"
            )

    def __enter__(self) -> "_SshBase64WriteFile":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is None:
            self.close()
        else:
            self.closed = True


class SshBase64FS:
    """Duck-typed SFTP fallback over SSH stdin/stdout base64 when Dropbear lacks sftp-server."""

    def __init__(self, ssh) -> None:
        self._ssh = ssh

    def open(self, remote_path: str, mode: str = "rb"):
        if "w" in mode:
            return _SshBase64WriteFile(self._ssh, remote_path)
        _, stdout, stderr = self._ssh.exec_command(
            f"base64 {_shq(remote_path)}",
            timeout=120.0,
        )
        raw_out = stdout.read()
        raw_err = stderr.read()
        rc = stdout.channel.recv_exit_status()
        if rc != 0:
            err_s = raw_err.decode("utf-8", "replace") if isinstance(raw_err, (bytes, bytearray)) else str(raw_err)
            raise FileNotFoundError(f"Remote read failed rc={rc} ({remote_path}): {err_s.strip()}")
        b64_bytes = raw_out if isinstance(raw_out, (bytes, bytearray)) else str(raw_out).encode("ascii", "ignore")
        return io.BytesIO(base64.b64decode(b64_bytes))

    def chmod(self, remote_path: str, mode: int) -> None:
        ssh_run(self._ssh, f"chmod {mode & 0o777:03o} {_shq(remote_path)}")

    def posix_rename(self, src_path: str, dst_path: str) -> None:
        ssh_run(self._ssh, f"mv -f {_shq(src_path)} {_shq(dst_path)}")

    def close(self) -> None:
        pass


def open_remote_fs(ssh):
    """Return native SFTP client or fall back to SshBase64FS when Dropbear rejects SFTP subsystem."""
    try:
        return ssh.open_sftp()
    except Exception as exc:
        msg = str(exc).lower()
        if (
            isinstance(exc, EOFError)
            or exc.__class__.__name__ in ("SSHException", "ChannelException")
            or any(tok in msg for tok in ("eof", "negotiation", "subsystem", "sftp"))
        ):
            return SshBase64FS(ssh)
        raise


def _shq(val: str) -> str:
    return "'" + val.replace("'", "'\\''") + "'"


class UsbNetModeSwitchTimeoutError(TimeoutError):
    """Raised when an intentional USB gadget mode transition times out re-enumerating (not a flash failure)."""


VALID_USB_NET_MODES = ("auto", "preserve", "ncm", "ecm", "rndis")


def resolve_host_usb_net_plan(
    *,
    host_platform: str,
    current_mode: str,
    requested_mode: str = "auto",
    persist_mode: bool = False,
) -> dict[str, Any]:
    """Host-adapter layer decision for OpenWrt USB network mode.

    Defaults to preserving whichever USB gadget mode (ncm/ecm/rndis) is already working over SSH,
    never forcing permanent RNDIS across macOS/Linux/Android/Windows unless explicitly requested.
    """
    if requested_mode not in VALID_USB_NET_MODES:
        raise ValueError(f"Unsupported USB net mode {requested_mode!r}; expected {VALID_USB_NET_MODES}")
    norm_cur = current_mode.strip().lower() or "unknown"
    if requested_mode in ("auto", "preserve"):
        return {
            "host_platform": host_platform,
            "install_usb_net_mode": norm_cur,
            "final_usb_net_mode": norm_cur,
            "switch_required": False,
            "permanent": False,
            "expected_disconnect": False,
            "reason": f"Preserving already-working USB gadget mode ({norm_cur}) on host '{host_platform}'",
        }
    switch_req = requested_mode != norm_cur
    return {
        "host_platform": host_platform,
        "install_usb_net_mode": norm_cur,
        "final_usb_net_mode": requested_mode,
        "switch_required": switch_req or persist_mode,
        "permanent": bool(persist_mode),
        "expected_disconnect": switch_req,
        "reason": (
            f"Explicit host-requested USB mode transition {norm_cur} -> {requested_mode} (permanent={bool(persist_mode)})"
        ),
    }


def _prepare_host_rndis(
    static_ip: str = "192.168.77.12",
    *,
    target_iface: str | None = None,
    usb_topology: dict[str, Any] | None = None,
) -> dict[str, Any]:
    res: dict[str, Any] = {}
    res["usbflags_cleared"] = clear_negative_usbflags_rndis()
    try:
        res["driver_bind"] = bind_inbox_rndis_driver(install=True)
    except Exception as exc:
        res["driver_bind_note"] = str(exc)
    res["network_isolation"] = isolate_usb_rndis_adapter(
        static_ip=static_ip,
        target_iface=target_iface,
        usb_topology=usb_topology,
    )
    return res


def _extract_win_broken_ncm_com_port(
    pnp_devices: list[dict[str, Any]],
    *,
    usb_topology: dict[str, Any] | None = None,
) -> str | None:
    """Detect Windows broken U30PRO CDC NCM + working MI_02 COM port without hijacking healthy NICs."""
    target_devs = [
        d for d in pnp_devices
        if "VID_1D6B&PID_0104" in str(d.get("InstanceId", "")).upper()
    ]
    if not target_devs:
        return None
    if usb_topology and usb_topology.get("serial"):
        tok = str(usb_topology["serial"]).strip().upper()
        filtered = [d for d in target_devs if tok in str(d.get("InstanceId", "")).upper()]
        if filtered:
            target_devs = filtered

    if any(
        str(d.get("Class", "")).lower() == "net" and str(d.get("Status", "")).lower() == "ok"
        for d in target_devs
    ):
        return None

    has_broken_ncm = any(
        str(d.get("Status", "")).lower() != "ok"
        and (
            str(d.get("Class", "")).lower() == "net"
            or "MI_00" in str(d.get("InstanceId", "")).upper()
            or "NCM" in str(d.get("FriendlyName", "")).upper()
        )
        for d in target_devs
    )
    if not has_broken_ncm:
        return None

    for d in target_devs:
        inst = str(d.get("InstanceId", "")).upper()
        cls = str(d.get("Class", "")).lower()
        status = str(d.get("Status", "")).lower()
        name = str(d.get("FriendlyName", ""))
        if status == "ok" and (cls == "ports" or "COM" in name.upper()) and "MI_02" in inst:
            m = re.search(r"\((COM\d+)\)", name, re.IGNORECASE)
            if m:
                return m.group(1).upper()
    return None


def _find_win_broken_ncm_serial_port(*, usb_topology: dict[str, Any] | None = None) -> str | None:
    """Query Windows PnP once for a broken VID_1D6B&PID_0104 CDC NCM interface paired with MI_02 COM port."""
    if detect_host_platform() != "win64":
        return None
    ps_cmd = (
        "@(Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'USB\\VID_1D6B&PID_0104*' } | "
        "Select-Object InstanceId,Status,Class,FriendlyName) | ConvertTo-Json -Compress"
    )
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            **win_no_window_kwargs(),
        )
        if res.returncode != 0 or not res.stdout.strip():
            return None
        parsed = json.loads(res.stdout.strip())
        devs = [parsed] if isinstance(parsed, dict) else list(parsed)
    except Exception:
        return None
    return _extract_win_broken_ncm_com_port(devs, usb_topology=usb_topology)


def _recover_broken_ncm_via_serial(
    com_port: str,
    *,
    passwords: tuple[str, ...] = ("", "root"),
) -> dict[str, Any]:
    """Switch broken Win10 CDC NCM device to RNDIS over MI_02 serial console and commit _b boot."""
    import serial  # type: ignore

    ser = serial.Serial(com_port, baudrate=115200, timeout=0.4, write_timeout=2.0)
    try:
        def _read_for(dur: float) -> str:
            end = time.monotonic() + dur
            chunks: list[str] = []
            while time.monotonic() < end:
                n = ser.in_waiting
                data = ser.read(n if n > 0 else 1)
                if data:
                    chunks.append(data.decode("utf-8", "replace"))
                else:
                    time.sleep(0.05)
            return "".join(chunks)

        ser.reset_input_buffer()
        ser.write(b"\r\n")
        ser.flush()
        banner = _read_for(1.2)
        if "press enter to activate" in banner.lower():
            ser.write(b"\r\n")
            ser.flush()
            banner += _read_for(0.8)
        if "login:" in banner.lower():
            for pw in passwords:
                ser.write(b"root\r\n")
                ser.flush()
                resp = _read_for(0.8)
                if "password:" in resp.lower():
                    ser.write((pw + "\r\n").encode("utf-8"))
                    ser.flush()
                    resp += _read_for(0.8)
                if "#" in resp or "root@" in resp:
                    break

        def _exec(cmd: str, wait_sec: float = 3.0) -> str:
            tag = f"__F50SER_{secrets.token_hex(4)}__"
            ser.reset_input_buffer()
            ser.write(f"echo {tag}_B; {cmd}; echo {tag}_E:$?\r\n".encode("utf-8"))
            ser.flush()
            end = time.monotonic() + wait_sec
            buf = ""
            while time.monotonic() < end:
                n = ser.in_waiting
                data = ser.read(n if n > 0 else 1)
                if data:
                    buf += data.decode("utf-8", "replace")
                    if re.search(rf"{tag}_E:\d+", buf):
                        break
                else:
                    time.sleep(0.05)
            m_body = re.search(rf"{tag}_B\s*(.*?)\s*{tag}_E:\d+", buf, re.DOTALL)
            return m_body.group(1) if m_body else buf

        model_out = _exec("cat /etc/mu300/model 2>/dev/null || echo unknown", wait_sec=2.5)
        if not any(ln.strip() == "f50pro" for ln in model_out.splitlines()):
            raise RuntimeError(f"Serial port {com_port} did not identify as f50pro: {model_out!r}")

        _exec("/opt/mu300/bin/mu300-next-boot linux", wait_sec=3.0)
        _exec(
            "uci set u30pro.usb=usb && uci set u30pro.usb.mode=rndis && uci commit u30pro && "
            "/usr/libexec/unisoc-modem/device-usb set-net rndis permanent 1",
            wait_sec=4.0,
        )
        ser.write(
            b"setsid sh -c 'sleep 0.5; /usr/sbin/u30pro-usb stop; sleep 1; /usr/sbin/u30pro-usb start rndis' "
            b"</dev/null >/dev/null 2>&1 &\r\n"
        )
        ser.flush()
        time.sleep(0.5)
        return {"recovered": True, "com_port": com_port, "target_mode": "rndis"}
    finally:
        try:
            ser.close()
        except Exception:
            pass


def wait_for_openwrt_ssh(
    host: str = "192.168.77.1",
    *,
    passwords: tuple[str, ...] = ("", "root"),
    timeout: int = 120,
    isolate_host: bool = True,
    static_ip: str = "192.168.77.12",
    target_iface: str | None = None,
    usb_topology: dict[str, Any] | None = None,
    auto_recover_broken_ncm_serial: bool = True,
):
    """Poll until target F50 Pro USB interface is isolated and OpenWrt SSH responds cleanly."""
    deadline = time.monotonic() + timeout
    first_poll_at = time.monotonic()
    iso_done = False
    ncm_serial_attempted = False
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        if isolate_host:
            try:
                _prepare_host_rndis(static_ip=static_ip, target_iface=target_iface, usb_topology=usb_topology)
                iso_done = True
            except Exception:
                pass
        try:
            ssh = connect_ssh(host, passwords=passwords, timeout=5.0)
            rc, out, _ = ssh_run(ssh, "cat /etc/mu300/model 2>/dev/null", check=False, timeout=5.0)
            if rc == 0 and out.strip() == "f50pro":
                if isolate_host and not iso_done:
                    _prepare_host_rndis(static_ip=static_ip, target_iface=target_iface, usb_topology=usb_topology)
                return ssh
            ssh.close()
        except Exception as exc:
            last_err = exc
        if (
            auto_recover_broken_ncm_serial
            and not ncm_serial_attempted
            and detect_host_platform() == "win64"
            and (time.monotonic() - first_poll_at) >= 5.0
        ):
            com_port = _find_win_broken_ncm_serial_port(usb_topology=usb_topology)
            if com_port:
                ncm_serial_attempted = True
                try:
                    _recover_broken_ncm_via_serial(com_port, passwords=passwords)
                    time.sleep(4.0)
                    continue
                except Exception as exc_ser:
                    last_err = exc_ser
        time.sleep(2.5)
    raise TimeoutError(f"Timed out waiting for OpenWrt SSH at {host}: {last_err}")


def _ensure_rootfs_grown(ssh, sftp) -> dict[str, Any]:
    ow_dir = ASSETS_DIR / "openwrt-patch"
    grow_py = (ow_dir / "f50pro-rootfs-grow.py").read_bytes().replace(b"\r\n", b"\n")
    grow_init = (ow_dir / "f50pro-rootfs-grow-init").read_bytes().replace(b"\r\n", b"\n")
    sftp_put_bytes(sftp, grow_py, "/usr/sbin/f50pro-rootfs-grow.py", mode=0o755)
    sftp_put_bytes(sftp, grow_init, "/etc/init.d/f50pro-rootfs-grow", mode=0o755)
    ssh_run(ssh, "/etc/init.d/f50pro-rootfs-grow enable >/dev/null 2>&1 || true", check=False)
    _, out, _ = ssh_run(ssh, "/usr/bin/python3 /usr/sbin/f50pro-rootfs-grow.py")
    return json.loads(out.strip().splitlines()[-1])


def _ensure_board6_card_patch(ssh, sftp) -> str:
    remote_card = "/opt/mu300/lib/f50pro-card.sh"
    current = sftp_get_bytes(sftp, remote_card)
    cur_sha = sha256_bytes(current)
    if cur_sha == BOARD6_AFTER_SHA256:
        return cur_sha
    if cur_sha != BOARD6_BEFORE_SHA256:
        raise ValueError(f"Unexpected {remote_card} SHA-256: {cur_sha}")
    patch_bytes = (ASSETS_DIR / "openwrt-patch" / "f50pro-board6.patch").read_bytes().replace(b"\r\n", b"\n")
    sftp_put_bytes(sftp, patch_bytes, "/tmp/f50pro-board6.patch", mode=0o644)
    ssh_run(ssh, "cd / && patch -p1 -N -i /tmp/f50pro-board6.patch && rm -f /tmp/f50pro-board6.patch")
    new_sha = sha256_bytes(sftp_get_bytes(sftp, remote_card))
    if new_sha != BOARD6_AFTER_SHA256:
        raise RuntimeError(f"board_id=6 patch digest mismatch: {new_sha}")
    return new_sha


def _ensure_capacity_ui(sftp) -> dict[str, str]:
    ow_dir = ASSETS_DIR / "openwrt-patch"
    hashes = read_json(ow_dir / "ui-hashes.json")
    sftp_put_bytes(
        sftp,
        (ow_dir / "f50pro-capacity.uc").read_bytes().replace(b"\r\n", b"\n"),
        "/usr/share/ucode/mu300/f50pro-capacity.uc",
        mode=0o644,
    )
    results: dict[str, str] = {}
    for rel, pair in hashes.items():
        rpath = "/" + rel.lstrip("/")
        cur_sha = sha256_bytes(sftp_get_bytes(sftp, rpath))
        if cur_sha == pair["after"]:
            results[rel] = cur_sha
            continue
        if cur_sha != pair["before"]:
            raise ValueError(f"Unexpected revision of {rpath}: {cur_sha}")
        local_name = "dash.uc" if rel.endswith("dash.uc") else "home.js"
        payload = (ow_dir / local_name).read_bytes().replace(b"\r\n", b"\n")
        if sha256_bytes(payload) != pair["after"]:
            raise ValueError(f"Bundled UI asset digest mismatch for {local_name}")
        sftp_put_bytes(sftp, payload, rpath, mode=0o644)
        results[rel] = pair["after"]
    return results


def _ensure_5s_buttons(ssh, sftp, *, tools_dir: Path) -> dict[str, Any]:
    btn_dir = ASSETS_DIR / "openwrt-patch" / "buttons"
    keys_bin = tools_dir / "openwrt-base" / "mu300-keys"
    if not keys_bin.is_file():
        raise FileNotFoundError(f"Missing {keys_bin}; run fetch_assets.py first.")
    sftp_put_bytes(sftp, keys_bin.read_bytes(), "/usr/sbin/mu300-keys", mode=0o755)
    sftp_put_bytes(sftp, (btn_dir / "f50pro-key-action").read_bytes().replace(b"\r\n", b"\n"), "/opt/mu300/bin/f50pro-key-action", mode=0o755)
    sftp_put_bytes(sftp, (btn_dir / "buttons").read_bytes().replace(b"\r\n", b"\n"), "/usr/libexec/unisoc-modem/buttons", mode=0o755)
    sftp_put_bytes(sftp, (btn_dir / "buttons.js").read_bytes().replace(b"\r\n", b"\n"), "/www/luci-static/resources/mu300/buttons.js", mode=0o644)
    sftp_put_bytes(sftp, (btn_dir / "rc.local").read_bytes().replace(b"\r\n", b"\n"), "/etc/rc.local", mode=0o755)

    meta = read_json(btn_dir / "mu300-sysd-5s-meta.json")
    sysd_path = "/opt/mu300/bin/mu300-sysd"
    sysd_raw = sftp_get_bytes(sftp, sysd_path)
    sysd_txt = sysd_raw.decode("utf-8")
    if "MU300_KEYS_LONG_MS" in sysd_txt:
        sysd_state = "already_patched"
    else:
        if sha256_bytes(sysd_raw) != meta["orig_sha256"]:
            raise ValueError(f"Unexpected {sysd_path} SHA-256: {sha256_bytes(sysd_raw)}")
        if sysd_txt.count(meta["target"]) != 1:
            raise ValueError("5s timeout hook marker not unique in mu300-sysd")
        patched = sysd_txt.replace(meta["target"], meta["replacement"]).encode("utf-8")
        sftp_put_bytes(sftp, patched, sysd_path, mode=0o755)
        sysd_state = "patched"

    ssh_run(
        ssh,
        "uci set unisoc_modem.main.f50pro_button_long='system-switch' && uci commit unisoc_modem",
    )
    return {"mu300_sysd": sysd_state, "long_action": "system-switch"}


def _install_openclash_offline(ssh, sftp, *, cache_dir: Path, tools_dir: Path) -> dict[str, Any]:
    oc_dir = tools_dir / "openclash-offline"
    if not oc_dir.is_dir():
        raise FileNotFoundError(f"Missing OpenClash offline directory {oc_dir}; run fetch_assets.py without --no-openclash.")
    ipks = sorted(oc_dir.glob("**/*.apk")) or sorted(oc_dir.glob("**/*.ipk"))
    cores = sorted(oc_dir.glob("**/mihomo-linux-arm64*.gz"))
    geosite = next(oc_dir.glob("**/GeoSite.dat"), None)
    mmdb = next(oc_dir.glob("**/Country.mmdb"), None)
    if not cores or not geosite or not mmdb:
        raise FileNotFoundError(f"Incomplete OpenClash offline pack in {oc_dir}")

    ssh_run(ssh, "mkdir -p /tmp/oc-pkgs /etc/openclash/core /etc/openclash/config")
    pkg_paths = []
    for p in ipks:
        dst = f"/tmp/oc-pkgs/{p.name}"
        sftp_put_bytes(sftp, p.read_bytes(), dst, mode=0o644)
        pkg_paths.append(_shq(dst))

    if pkg_paths:
        # Handle either apk (OpenWrt 25.12+) or opkg cleanly
        ssh_run(
            ssh,
            f"if command -v apk >/dev/null 2>&1; then apk add --no-network --allow-untrusted {' '.join(pkg_paths)}; "
            f"else opkg install {' '.join(pkg_paths)}; fi",
            timeout=180,
        )

    import gzip

    core_bin = gzip.decompress(cores[0].read_bytes())
    sftp_put_bytes(sftp, core_bin, "/etc/openclash/core/clash_meta", mode=0o755)
    sftp_put_bytes(sftp, geosite.read_bytes(), "/etc/openclash/GeoSite.dat", mode=0o644)
    sftp_put_bytes(sftp, mmdb.read_bytes(), "/etc/openclash/Country.mmdb", mode=0o644)

    tpl_dir = ASSETS_DIR / "openwrt-patch" / "openclash-clean"
    sftp_put_bytes(
        sftp,
        (tpl_dir / "template.yaml").read_bytes().replace(b"\r\n", b"\n"),
        "/tmp/openclash-template.yaml",
        mode=0o644,
    )
    apply_sh = (tpl_dir / "openclash-uci-apply.sh").read_bytes().replace(b"\r\n", b"\n")
    sftp_put_bytes(sftp, apply_sh, "/tmp/openclash-uci-apply.sh", mode=0o755)
    ssh_run(ssh, "/bin/sh /tmp/openclash-uci-apply.sh && rm -rf /tmp/oc-pkgs /tmp/openclash-uci-apply.sh", timeout=120)
    return {"packages": len(pkg_paths), "core_bytes": len(core_bin), "template": "/etc/openclash/config/template.yaml"}


def generate_strong_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _probe_remote_identity_and_usb_mode(ssh) -> dict[str, str]:
    """Read non-PII hardware board_id, hashed machine marker, and active USB net mode over SSH."""
    _, out, _ = ssh_run(
        ssh,
        "printf 'board_id=%s\\ncmdline=%s\\nusb_get=%s\\nusb_mode=%s\\nhost_hash=%s\\n' "
        "\"$(cat /proc/driver/board_id 2>/dev/null || echo unknown)\" "
        "\"$(tr '\\r\\n' '  ' </proc/cmdline 2>/dev/null || true)\" "
        "\"$(/usr/libexec/unisoc-modem/device-usb get 2>/dev/null || true)\" "
        "\"$(uci -q get u30pro.usb.mode || sed -n 's/^mode=//p' /etc/unisoc-modem/usb-boot.conf 2>/dev/null | head -n 1 || echo unknown)\" "
        "\"$(sha256sum /etc/dropbear/dropbear_ed25519_host_key 2>/dev/null | cut -d' ' -f1 || cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)\"",
        check=False,
    )
    res = {"board_id": "unknown", "usb_mode": "unknown", "host_hash": "unknown"}
    cmdline = ""
    usb_get_raw = ""
    for ln in out.splitlines():
        if "=" in ln:
            k, v = ln.split("=", 1)
            key = k.strip()
            val = v.strip()
            if key == "cmdline":
                cmdline = val
            elif key == "usb_get":
                usb_get_raw = val
            elif key in res and val:
                res[key] = val
    if res["board_id"] == "unknown" and cmdline:
        m_bid = re.search(r"\bzteboot\.zte_boardid=(\d+)\b", cmdline)
        if m_bid:
            res["board_id"] = m_bid.group(1)
    if usb_get_raw.startswith("{"):
        try:
            ujson = json.loads(usb_get_raw)
            mode_val = str(ujson.get("net_current") or ujson.get("net_mode") or "").strip().lower()
            if mode_val and mode_val != "unknown":
                res["usb_mode"] = mode_val
        except json.JSONDecodeError:
            pass
    return res


def _apply_usb_net_mode_transition(
    ssh,
    *,
    plan: dict[str, Any],
    pre_identity: dict[str, str],
    openwrt_host: str,
    pw_candidates: tuple[str, ...],
    isolate_host: bool,
    target_iface: str | None,
    usb_topology: dict[str, Any] | None,
    out_dir: Path | None,
    reconnect_timeout: int = 90,
) -> tuple[Any, dict[str, Any]]:
    """Apply an explicit USB gadget mode change cleanly, handling expected disconnect and re-enumeration."""
    target_mode = plan["final_usb_net_mode"]
    scope = "permanent" if plan["permanent"] else "once"
    intent = {
        "from_mode": plan["install_usb_net_mode"],
        "to_mode": target_mode,
        "scope": scope,
        "permanent": plan["permanent"],
        "expected_disconnect": plan["expected_disconnect"],
        "pre_board_id": pre_identity["board_id"],
        "pre_host_hash": pre_identity["host_hash"],
        "expected_disconnect_observed": False,
        "reconnected": False,
    }
    if out_dir is not None:
        write_json(out_dir / "usb_net_transition.json", intent)

    cfg_cmd = (
        f"uci set u30pro.usb=usb && uci set u30pro.usb.mode={_shq(target_mode)} && uci commit u30pro && "
        f"/usr/libexec/unisoc-modem/device-usb set-net {_shq(target_mode)} {scope} 1 >/dev/null"
    )
    if plan["expected_disconnect"]:
        # device-usb set-net updates persistent/once config only; detach gadget restart so SSH tears down cleanly.
        cfg_cmd += (
            f" && setsid sh -c 'sleep 0.5; /usr/sbin/u30pro-usb stop; sleep 1; "
            f"/usr/sbin/u30pro-usb start \"$1\"' _ {_shq(target_mode)} </dev/null >/dev/null 2>&1 &"
        )
    try:
        ssh_run(ssh, cfg_cmd, timeout=25)
    except (EOFError, OSError, RuntimeError):
        # USB gadget mode switch tears down CDC-NCM/ECM/RNDIS immediately; disconnect is expected, NOT flash failure!
        intent["expected_disconnect_observed"] = True

    if not plan["expected_disconnect"]:
        intent["reconnected"] = True
        if out_dir is not None:
            write_json(out_dir / "usb_net_transition.json", intent)
        return ssh, intent

    try:
        ssh.close()
    except Exception:
        pass
    time.sleep(2.0)

    try:
        ssh2 = wait_for_openwrt_ssh(
            openwrt_host,
            passwords=pw_candidates,
            timeout=reconnect_timeout,
            isolate_host=isolate_host,
            target_iface=target_iface,
            usb_topology=usb_topology,
        )
    except TimeoutError as exc:
        if out_dir is not None:
            intent["timeout_error"] = str(exc)
            write_json(out_dir / "usb_net_transition.json", intent)
        raise UsbNetModeSwitchTimeoutError(
            f"Timed out waiting for F50 Pro USB re-enumeration after {intent['from_mode']} -> {target_mode} switch: {exc}"
        ) from exc

    post_identity = _probe_remote_identity_and_usb_mode(ssh2)
    if (
        pre_identity["board_id"] != "unknown"
        and post_identity["board_id"] != "unknown"
        and pre_identity["board_id"] != post_identity["board_id"]
    ) or (
        pre_identity["host_hash"] != "unknown"
        and post_identity["host_hash"] != "unknown"
        and pre_identity["host_hash"] != post_identity["host_hash"]
    ):
        ssh2.close()
        raise RuntimeError(
            f"Target device swapped during USB network mode re-enumeration: "
            f"expected board={pre_identity['board_id']}/host={pre_identity['host_hash'][:12]} "
            f"got board={post_identity['board_id']}/host={post_identity['host_hash'][:12]}"
        )
    intent["reconnected"] = True
    intent["post_usb_mode"] = post_identity["usb_mode"]
    if out_dir is not None:
        write_json(out_dir / "usb_net_transition.json", intent)
    return ssh2, intent


def _set_root_password_ssh(ssh, applied_pw: str) -> None:
    """Set OpenWrt root password reliably with interactive PTY fallback for picky BusyBox/Dropbear builds."""
    cmd = f"printf '%s\\n%s\\n' {_shq(applied_pw)} {_shq(applied_pw)} | passwd root >/dev/null"
    try:
        ssh_run(ssh, cmd, check=True, timeout=30.0)
    except Exception as exc:
        exec_fn = getattr(ssh, "exec_command", None)
        if not callable(exec_fn):
            raise
        stdin, stdout, stderr = exec_fn("passwd root", timeout=30.0, get_pty=True)
        stdin.write(f"{applied_pw}\n")
        stdin.flush()
        time.sleep(0.3)
        stdin.write(f"{applied_pw}\n")
        stdin.flush()
        if getattr(stdin, "channel", None) is not None:
            stdin.channel.shutdown_write()
        rc = stdout.channel.recv_exit_status()
        if rc != 0:
            raw_out = stdout.read()
            raw_err = stderr.read()
            raise RuntimeError(
                f"passwd root PTY fallback failed rc={rc}: out={raw_out!r} err={raw_err!r}"
            ) from exc


def provision_openwrt(
    *,
    profile_id: str,
    openwrt_host: str = "192.168.77.1",
    wifi_ssid: str = "F50Pro-OpenWrt",
    wifi_password: str | None = None,
    root_password: str | None = None,
    generate_password: bool = False,
    zonename: str = "Asia/Shanghai",
    timezone: str = "CST-8",
    usb_net_mode: str = "auto",
    usb_net_persist: bool = False,
    target_iface: str | None = None,
    usb_topology: dict[str, Any] | None = None,
    tools_dir: Path = DEFAULT_TOOLS_DIR,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    include_openclash: bool = False,
    isolate_host: bool = True,
    out_dir: Path | None = None,
    reboot_after: bool = True,
) -> dict[str, Any]:
    """Configure OpenWrt _b after flashing without forcing permanent RNDIS across all host OSes."""
    if profile_id not in PROFILES or not PROFILES[profile_id]["openwrt"]:
        raise ValueError(f"Profile {profile_id} does not include OpenWrt")

    host_plat = detect_host_platform()
    pw_candidates: tuple[str, ...] = ("", "root")
    if root_password:
        pw_candidates = (root_password, "", "root")

    ssh = wait_for_openwrt_ssh(
        openwrt_host,
        passwords=pw_candidates,
        isolate_host=isolate_host,
        target_iface=target_iface,
        usb_topology=usb_topology,
    )
    applied_pw = root_password
    if not applied_pw and generate_password:
        applied_pw = generate_strong_password()

    transition_meta: dict[str, Any] | None = None
    try:
        remote_pre = _probe_remote_identity_and_usb_mode(ssh)
        board_id = remote_pre["board_id"]
        usb_plan = resolve_host_usb_net_plan(
            host_platform=host_plat,
            current_mode=remote_pre["usb_mode"],
            requested_mode=usb_net_mode,
            persist_mode=usb_net_persist,
        )

        # Commit permanent boot to OpenWrt _b immediately so misc tries=3 trial budget cannot roll back mid-run.
        ssh_run(ssh, "/opt/mu300/bin/mu300-next-boot linux")

        sftp = open_remote_fs(ssh)
        grow_res = _ensure_rootfs_grown(ssh, sftp)
        board6_sha = _ensure_board6_card_patch(ssh, sftp)
        ui_res = _ensure_capacity_ui(sftp)
        btn_res = _ensure_5s_buttons(ssh, sftp, tools_dir=tools_dir)

        cmds = [
            "uci set system.@system[0].hostname='F50Pro'",
            f"uci set system.@system[0].zonename={_shq(zonename)}",
            f"uci set system.@system[0].timezone={_shq(timezone)}",
            "uci set unisoc_modem.main.at_port='/dev/stty_nr2'",
            "uci set unisoc_modem.main.sim_slots='2'",
            "uci set unisoc_modem.main.platform_defaults='u30pro'",
            "uci set unisoc_modem.main.wifi_device='phy0-ap0'",
            "uci set luci.main.lang='zh_cn'",
            "uci set luci.main.mediaurlbase='/luci-static/aurora'",
            "uci -q delete network.wan.device || true",
            f"WIFI_SEC=default_radio0; uci -q get wireless.default_radio0 >/dev/null || WIFI_SEC=@wifi-iface[0]; uci set wireless.$WIFI_SEC.ssid={_shq(wifi_ssid)}",
            f"if [ -f /etc/mu300/hotspot.conf ]; then (grep -v '^SSID=' /etc/mu300/hotspot.conf; printf 'SSID=%s\\n' {_shq(wifi_ssid)}) > /tmp/hotspot.conf.new && mv /tmp/hotspot.conf.new /etc/mu300/hotspot.conf; fi",
        ]
        if wifi_password:
            cmds.extend([
                "uci set wireless.$WIFI_SEC.encryption='psk2+ccmp'",
                f"uci set wireless.$WIFI_SEC.key={_shq(wifi_password)}",
                f"if [ -f /etc/mu300/hotspot.conf ]; then (grep -v '^PSK=' /etc/mu300/hotspot.conf; printf 'PSK=%s\\n' {_shq(wifi_password)}) > /tmp/hotspot.conf.new && mv /tmp/hotspot.conf.new /etc/mu300/hotspot.conf; fi",
            ])
        cmds.extend([
            "uci commit system",
            "uci commit unisoc_modem",
            "uci commit luci",
            "uci commit network",
            "uci commit wireless",
            "/etc/init.d/f50pro-leds enable >/dev/null 2>&1 || true",
            "/etc/init.d/f50pro-leds restart >/dev/null 2>&1 || true",
            "/etc/init.d/mu300-sysd restart >/dev/null 2>&1 || true",
            "/etc/init.d/rpcd restart >/dev/null 2>&1 || true",
            "/etc/init.d/uhttpd restart >/dev/null 2>&1 || true",
            "wifi reload >/dev/null 2>&1 || true",
        ])
        ssh_run(ssh, " && ".join(cmds), timeout=90)

        if usb_plan["switch_required"]:
            ssh, transition_meta = _apply_usb_net_mode_transition(
                ssh,
                plan=usb_plan,
                pre_identity=remote_pre,
                openwrt_host=openwrt_host,
                pw_candidates=pw_candidates,
                isolate_host=isolate_host,
                target_iface=target_iface,
                usb_topology=usb_topology,
                out_dir=out_dir,
            )
            sftp = open_remote_fs(ssh)

        oc_res = None
        if include_openclash:
            oc_res = _install_openclash_offline(ssh, sftp, cache_dir=cache_dir, tools_dir=tools_dir)

        if applied_pw:
            _set_root_password_ssh(ssh, applied_pw)
            pw_candidates = (applied_pw,)

        # Confirm permanent boot to OpenWrt _b and snapshot exact verified BCAB block
        ssh_run(ssh, "/opt/mu300/bin/mu300-next-boot linux")
        ssh_run(ssh, "dd if=/dev/block/by-name/misc bs=1 skip=2048 count=32 of=/tmp/known-good-b-bcab.bin 2>/dev/null")
        bc_bytes = sftp_get_bytes(sftp, "/tmp/known-good-b-bcab.bin")
        bc_info = parse_boot_control(b"\x00" * 2048 + bc_bytes)
        if bc_info["suffix"] != "_b":
            raise RuntimeError(f"Expected suffix=_b after mu300-next-boot linux, got {bc_info}")

        cred_path: str | None = None
        if out_dir is not None:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "known-good-b-bcab.bin").write_bytes(bc_bytes)
            if applied_pw:
                cfile = out_dir / "openwrt-credentials.json"
                write_json(
                    cfile,
                    {"host": openwrt_host, "username": "root", "password": applied_pw},
                )
                cred_path = str(cfile)

        if reboot_after:
            ssh_run(ssh, "sync && reboot", check=False, timeout=5)
    finally:
        ssh.close()

    if reboot_after:
        time.sleep(10)
        ssh2 = wait_for_openwrt_ssh(
            openwrt_host,
            passwords=pw_candidates,
            timeout=150,
            isolate_host=isolate_host,
            target_iface=target_iface,
            usb_topology=usb_topology,
        )
        ssh2.close()

    result = {
        "status": "OPENWRT_PROVISIONED",
        "board_id": board_id,
        "rootfs_grow": grow_res,
        "board6_card_sha256": board6_sha,
        "ui_patches": ui_res,
        "buttons": btn_res,
        "wifi_ssid": wifi_ssid,
        "wifi_device": "phy0-ap0",
        "zonename": zonename,
        "timezone": timezone,
        "install_usb_net_mode": usb_plan["install_usb_net_mode"],
        "final_usb_net_mode": usb_plan["final_usb_net_mode"],
        "usb_mode": usb_plan["final_usb_net_mode"],
        "usb_net_plan": usb_plan,
        "usb_net_transition": transition_meta,
        "openclash": oc_res,
        "slot_b_bcab": bc_info,
        "password_updated": bool(applied_pw),
        "credentials_file": cred_path,
    }
    if out_dir is not None:
        write_json(out_dir / "openwrt_provision_report.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, choices=[p for p, v in PROFILES.items() if v["openwrt"]])
    parser.add_argument("--host", default="192.168.77.1")
    parser.add_argument("--wifi-ssid", default="F50Pro-OpenWrt")
    parser.add_argument("--wifi-password")
    parser.add_argument("--root-password")
    parser.add_argument("--generate-password", action="store_true")
    parser.add_argument("--zonename", default="Asia/Shanghai")
    parser.add_argument("--timezone", default="CST-8")
    parser.add_argument("--usb-net-mode", default="auto", choices=list(VALID_USB_NET_MODES))
    parser.add_argument("--usb-net-persist", action="store_true", help="Persist USB net mode switch across reboots")
    parser.add_argument("--target-iface", help="Explicit USB network interface/service name to isolate")
    parser.add_argument("--openclash", action="store_true")
    parser.add_argument("--no-host-isolate", action="store_true")
    parser.add_argument("--no-reboot", action="store_true")
    parser.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--out-dir", type=Path)
    args = parser.parse_args()

    out = None
    if args.out_dir:
        out = args.out_dir if args.out_dir.is_absolute() else (REPO_ROOT / args.out_dir)
    res = provision_openwrt(
        profile_id=args.profile,
        openwrt_host=args.host,
        wifi_ssid=args.wifi_ssid,
        wifi_password=args.wifi_password,
        root_password=args.root_password,
        generate_password=args.generate_password,
        zonename=args.zonename,
        timezone=args.timezone,
        usb_net_mode=args.usb_net_mode,
        usb_net_persist=args.usb_net_persist,
        target_iface=args.target_iface,
        tools_dir=args.tools_dir,
        cache_dir=args.cache_dir,
        include_openclash=args.openclash,
        isolate_host=not args.no_host_isolate,
        out_dir=out,
        reboot_after=not args.no_reboot,
    )
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
