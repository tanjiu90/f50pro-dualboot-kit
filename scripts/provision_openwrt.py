"""OpenWrt provisioning over SSH: 2 GiB rootfs grow, board_id=6, capacity UI, LEDs, 5s button, optional OpenClash."""
from __future__ import annotations

import argparse
import io
import json
import posixpath
import secrets
import string
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
    parse_boot_control,
    read_json,
    sha256_bytes,
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


def _shq(val: str) -> str:
    return "'" + val.replace("'", "'\\''") + "'"


def _prepare_host_rndis(static_ip: str = "192.168.77.12") -> dict[str, Any]:
    res: dict[str, Any] = {}
    res["usbflags_cleared"] = clear_negative_usbflags_rndis()
    try:
        res["driver_bind"] = bind_inbox_rndis_driver(install=True)
    except Exception as exc:
        res["driver_bind_note"] = str(exc)
    res["network_isolation"] = isolate_usb_rndis_adapter(static_ip=static_ip)
    return res


def wait_for_openwrt_ssh(
    host: str = "192.168.77.1",
    *,
    passwords: tuple[str, ...] = ("", "root"),
    timeout: int = 120,
    isolate_host: bool = True,
    static_ip: str = "192.168.77.12",
):
    """Poll until host RNDIS binds and OpenWrt SSH responds cleanly."""
    deadline = time.monotonic() + timeout
    iso_done = False
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        if isolate_host:
            try:
                _prepare_host_rndis(static_ip=static_ip)
                iso_done = True
            except Exception:
                pass
        try:
            ssh = connect_ssh(host, passwords=passwords, timeout=5.0)
            rc, out, _ = ssh_run(ssh, "cat /etc/mu300/model 2>/dev/null", check=False, timeout=5.0)
            if rc == 0 and out.strip() == "f50pro":
                if isolate_host and not iso_done:
                    _prepare_host_rndis(static_ip=static_ip)
                return ssh
            ssh.close()
        except Exception as exc:
            last_err = exc
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
    ssh_run(ssh, "patch --batch --forward --fuzz=0 -p1 -d / -i /tmp/f50pro-board6.patch && rm -f /tmp/f50pro-board6.patch")
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


def provision_openwrt(
    *,
    profile_id: str,
    openwrt_host: str = "192.168.77.1",
    wifi_ssid: str = "F50Pro-OpenWrt",
    wifi_password: str | None = None,
    root_password: str | None = None,
    generate_password: bool = False,
    tools_dir: Path = DEFAULT_TOOLS_DIR,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    include_openclash: bool = False,
    isolate_host: bool = True,
    out_dir: Path | None = None,
    reboot_after: bool = True,
) -> dict[str, Any]:
    """Configure OpenWrt _b after flashing and capture verified live known-good-b-bcab.bin."""
    if profile_id not in PROFILES or not PROFILES[profile_id]["openwrt"]:
        raise ValueError(f"Profile {profile_id} does not include OpenWrt")

    pw_candidates: tuple[str, ...] = ("", "root")
    if root_password:
        pw_candidates = (root_password, "", "root")

    ssh = wait_for_openwrt_ssh(
        openwrt_host,
        passwords=pw_candidates,
        isolate_host=isolate_host,
    )
    applied_pw = root_password
    if not applied_pw and generate_password:
        applied_pw = generate_strong_password()

    try:
        sftp = ssh.open_sftp()
        _, board_out, _ = ssh_run(ssh, "cat /proc/driver/board_id 2>/dev/null || echo unknown")
        grow_res = _ensure_rootfs_grown(ssh, sftp)
        board6_sha = _ensure_board6_card_patch(ssh, sftp)
        ui_res = _ensure_capacity_ui(sftp)
        btn_res = _ensure_5s_buttons(ssh, sftp, tools_dir=tools_dir)

        cmds = [
            "uci set system.@system[0].hostname='F50Pro'",
            "uci set system.@system[0].zonename='Asia/Shanghai'",
            "uci set system.@system[0].timezone='CST-8'",
            "uci set unisoc_modem.main.at_port='/dev/stty_nr2'",
            "uci set unisoc_modem.main.sim_slots='2'",
            "uci set unisoc_modem.main.platform_defaults='u30pro'",
            "uci set unisoc_modem.main.wifi_device='phy0-ap0'",
            "uci set luci.main.lang='zh_cn'",
            "uci set luci.main.mediaurlbase='/luci-static/aurora'",
            "uci -q delete network.wan.device || true",
            f"WIFI_SEC=default_radio0; uci -q get wireless.default_radio0 >/dev/null || WIFI_SEC=@wifi-iface[0]; uci set wireless.$WIFI_SEC.ssid={_shq(wifi_ssid)}",
            "uci set u30pro.usb=usb",
            "uci set u30pro.usb.mode='rndis'",
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
            "uci commit u30pro",
            "/usr/libexec/unisoc-modem/device-usb set-net rndis permanent 1 >/dev/null",
            "/etc/init.d/f50pro-leds enable >/dev/null 2>&1 || true",
            "/etc/init.d/f50pro-leds restart >/dev/null 2>&1 || true",
            "/etc/init.d/mu300-sysd restart >/dev/null 2>&1 || true",
            "/etc/init.d/rpcd restart >/dev/null 2>&1 || true",
            "/etc/init.d/uhttpd restart >/dev/null 2>&1 || true",
            "wifi reload >/dev/null 2>&1 || true",
        ])
        ssh_run(ssh, " && ".join(cmds), timeout=90)

        oc_res = None
        if include_openclash:
            oc_res = _install_openclash_offline(ssh, sftp, cache_dir=cache_dir, tools_dir=tools_dir)

        if applied_pw:
            ssh_run(ssh, f"printf '%s\\n%s\\n' {_shq(applied_pw)} {_shq(applied_pw)} | passwd root >/dev/null", check=True)
            pw_candidates = (applied_pw,)

        # Commit permanent boot to OpenWrt _b and snapshot exact verified BCAB block
        ssh_run(ssh, "/opt/mu300/bin/mu300-next-boot linux")
        ssh_run(ssh, "dd if=/dev/block/by-name/misc bs=1 skip=2048 count=32 of=/tmp/known-good-b-bcab.bin 2>/dev/null")
        bc_bytes = sftp_get_bytes(sftp, "/tmp/known-good-b-bcab.bin")
        bc_info = parse_boot_control(b"\x00" * 2048 + bc_bytes)
        if bc_info["suffix"] != "_b":
            raise RuntimeError(f"Expected suffix=_b after mu300-next-boot linux, got {bc_info}")

        if out_dir is not None:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "known-good-b-bcab.bin").write_bytes(bc_bytes)
            if applied_pw:
                write_json(
                    out_dir / "openwrt-credentials.json",
                    {"host": openwrt_host, "username": "root", "password": applied_pw},
                )

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
        )
        ssh2.close()

    result = {
        "status": "OPENWRT_PROVISIONED",
        "board_id": board_out.strip(),
        "rootfs_grow": grow_res,
        "board6_card_sha256": board6_sha,
        "ui_patches": ui_res,
        "buttons": btn_res,
        "wifi_ssid": wifi_ssid,
        "wifi_device": "phy0-ap0",
        "usb_mode": "rndis",
        "openclash": oc_res,
        "slot_b_bcab": bc_info,
        "password_updated": bool(applied_pw),
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
