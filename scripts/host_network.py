"""Cross-platform targeted F50 Pro USB network isolation, snapshot restore, and strict default-route auditing."""
from __future__ import annotations

import argparse
import ctypes as c
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from common import detect_host_platform, read_json, win_no_window_kwargs, write_json


class _GUID(c.Structure):
    _fields_ = [("data", c.c_ubyte * 16)]


class _DEVINFO_DATA(c.Structure):
    _fields_ = [
        ("size", c.c_ulong),
        ("guid", _GUID),
        ("devinst", c.c_ulong),
        ("reserved", c.c_void_p),
    ]


class _INSTALL_PARAMS(c.Structure):
    _fields_ = [
        ("size", c.c_ulong),
        ("flags", c.c_ulong),
        ("flags_ex", c.c_ulong),
        ("window", c.c_void_p),
        ("handler", c.c_void_p),
        ("context", c.c_void_p),
        ("queue", c.c_void_p),
        ("reserved_class", c.c_void_p),
        ("reserved", c.c_ulong),
        ("path", c.c_wchar * 260),
    ]


class _DRVINFO_DATA(c.Structure):
    _fields_ = [
        ("size", c.c_ulong),
        ("type", c.c_ulong),
        ("reserved", c.c_void_p),
        ("description", c.c_wchar * 256),
        ("manufacturer", c.c_wchar * 256),
        ("provider", c.c_wchar * 256),
        ("date_low", c.c_ulong),
        ("date_high", c.c_ulong),
        ("version", c.c_ulonglong),
    ]


def _ps(cmd: str) -> str:
    wrapped = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); " + cmd
    res = subprocess.run(
        ["powershell", "-NoProfile", "-Command", wrapped],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        **win_no_window_kwargs(),
    )
    if res.returncode != 0:
        raise RuntimeError(f"PowerShell failed ({res.returncode}): {(res.stderr or '').strip()}")
    return (res.stdout or "").strip()


def _run_cmd(cmd: list[str], *, check: bool = True, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
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
        raise RuntimeError(f"Command {' '.join(cmd)} failed ({res.returncode}): {(res.stderr or res.stdout).strip()}")
    return res


def _run_priv_posix(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a privileged system network command as root or non-interactive sudo."""
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        sudo = shutil.which("sudo")
        if sudo:
            res = _run_cmd([sudo, "-n", *cmd], check=False)
            if res.returncode == 0 or not check:
                return res
            raise PermissionError(
                f"Root privileges required for `{' '.join(cmd)}`. Re-run with sudo or configure interface manually."
            )
    return _run_cmd(cmd, check=check)


def select_target_usb_adapters(
    candidates: list[dict[str, Any]],
    *,
    target_iface: str | None = None,
    usb_topology: dict[str, Any] | None = None,
    include_zte_android: bool = False,
) -> dict[str, Any]:
    """Strictly select ONLY interfaces correlated to the target F50 Pro (rejecting generic phone RNDIS/USB docks)."""
    matched: list[dict[str, Any]] = []
    ignored: list[dict[str, Any]] = []

    for item in candidates:
        vid = str(item.get("vid", "")).lower().removeprefix("0x")
        pid = str(item.get("pid", "")).lower().removeprefix("0x")
        pnp_id = str(item.get("pnp_id", ""))
        name = str(item.get("name", ""))
        bsd_dev = str(item.get("device", ""))
        svc = str(item.get("network_service", ""))
        port_path = str(item.get("port_path", ""))
        serial = str(item.get("serial", ""))

        if target_iface:
            if target_iface not in (name, bsd_dev, svc):
                ignored.append({"candidate": name or bsd_dev, "reason": "not matching explicit target_iface"})
                continue

        is_f50_openwrt_vid = (vid == "1d6b" and pid == "0104") or ("VID_1D6B&PID_0104" in pnp_id.upper())
        is_f50_zte_vid = include_zte_android and (vid == "19d2" or "VID_19D2" in pnp_id.upper())
        if not (is_f50_openwrt_vid or is_f50_zte_vid):
            # Explicitly refuse matching solely on broad strings like RNDIS / USB Ethernet / CDC NCM / usb0
            ignored.append({"candidate": name or bsd_dev, "reason": "uncorrelated VID/PID (not F50 Pro 1d6b:0104)"})
            continue

        if usb_topology:
            topo_ok = True
            if usb_topology.get("port_path") and port_path and str(usb_topology["port_path"]) != port_path:
                topo_ok = False
            if usb_topology.get("serial") and serial and str(usb_topology["serial"]) != serial:
                topo_ok = False
            if not topo_ok:
                ignored.append({"candidate": name or bsd_dev, "reason": "USB topology/serial mismatch"})
                continue

        matched.append(item)

    ambiguous = len(matched) > 1 and not target_iface and not (usb_topology and (usb_topology.get("port_path") or usb_topology.get("serial")))
    return {
        "targets": matched,
        "ignored": ignored,
        "ambiguous": ambiguous,
    }


def clear_negative_usbflags_rndis() -> bool:
    """Clear negative cached OS descriptor flag on 1D6B:0104 Linux RNDIS gadget if present (Windows only)."""
    if sys.platform != "win32":
        return False
    out = _ps(
        "$k='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\UsbFlags\\1D6B01040612';"
        "if (Test-Path $k) { Remove-Item $k -Recurse -Force -ErrorAction SilentlyContinue; 'REMOVED' } else { 'CLEAN' }"
    )
    return "REMOVED" in out


def bind_inbox_rndis_driver(*, install: bool = True, target_instance_id: str | None = None) -> dict[str, Any]:
    """Bind Microsoft inbox netrndis.inf RNDIS6 driver specifically to present VID_1D6B&PID_0104 RNDIS child."""
    if sys.platform != "win32":
        return {"skipped": detect_host_platform(), "reason": "POSIX/Android uses native cdc_ncm/rndis_host kernel drivers"}
    raw = _ps(
        "Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match 'VID_1D6B&PID_0104' -and $_.FriendlyName -eq 'RNDIS' } "
        "| Select-Object -ExpandProperty InstanceId | ConvertTo-Json -Compress"
    )
    if not raw:
        return {"present_unbound_rndis": 0}
    ids = json.loads(raw)
    if isinstance(ids, str):
        ids = [ids]
    if target_instance_id:
        ids = [i for i in ids if target_instance_id.lower() in i.lower()]
    if len(ids) != 1:
        raise ValueError(f"Expected 1 correlated F50 Pro RNDIS device, found {len(ids)}: {ids}")

    setup = c.WinDLL("setupapi", use_last_error=True)
    newdev = c.WinDLL("newdev", use_last_error=True)
    setup.SetupDiCreateDeviceInfoList.restype = c.c_void_p
    setup.SetupDiCreateDeviceInfoList.argtypes = [c.c_void_p, c.c_void_p]
    setup.SetupDiOpenDeviceInfoW.argtypes = [c.c_void_p, c.c_wchar_p, c.c_void_p, c.c_ulong, c.POINTER(_DEVINFO_DATA)]
    setup.SetupDiGetDeviceInstallParamsW.argtypes = [c.c_void_p, c.POINTER(_DEVINFO_DATA), c.POINTER(_INSTALL_PARAMS)]
    setup.SetupDiSetDeviceInstallParamsW.argtypes = [c.c_void_p, c.POINTER(_DEVINFO_DATA), c.POINTER(_INSTALL_PARAMS)]
    setup.SetupDiBuildDriverInfoList.argtypes = [c.c_void_p, c.POINTER(_DEVINFO_DATA), c.c_ulong]
    setup.SetupDiEnumDriverInfoW.argtypes = [c.c_void_p, c.POINTER(_DEVINFO_DATA), c.c_ulong, c.c_ulong, c.POINTER(_DRVINFO_DATA)]
    setup.SetupDiSetSelectedDriverW.argtypes = [c.c_void_p, c.POINTER(_DEVINFO_DATA), c.POINTER(_DRVINFO_DATA)]
    setup.SetupDiDestroyDeviceInfoList.argtypes = [c.c_void_p]
    newdev.DiInstallDevice.argtypes = [c.c_void_p, c.c_void_p, c.POINTER(_DEVINFO_DATA), c.POINTER(_DRVINFO_DATA), c.c_ulong, c.POINTER(c.c_int)]

    def chk(val: int) -> None:
        if not val:
            raise c.WinError(c.get_last_error())

    handle = setup.SetupDiCreateDeviceInfoList(None, None)
    if handle == c.c_void_p(-1).value:
        raise c.WinError(c.get_last_error())
    try:
        dev = _DEVINFO_DATA(size=c.sizeof(_DEVINFO_DATA))
        chk(setup.SetupDiOpenDeviceInfoW(handle, ids[0], None, 0, c.byref(dev)))
        params = _INSTALL_PARAMS(size=c.sizeof(_INSTALL_PARAMS))
        chk(setup.SetupDiGetDeviceInstallParamsW(handle, c.byref(dev), c.byref(params)))
        params.flags |= 0x00010000 | 0x00800000
        params.flags_ex |= 0x00000800
        params.path = r"C:\Windows\INF\netrndis.inf"
        chk(setup.SetupDiSetDeviceInstallParamsW(handle, c.byref(dev), c.byref(params)))
        chk(setup.SetupDiBuildDriverInfoList(handle, c.byref(dev), 1))
        chosen = None
        candidates = []
        idx = 0
        while True:
            drv = _DRVINFO_DATA(size=c.sizeof(_DRVINFO_DATA))
            if not setup.SetupDiEnumDriverInfoW(handle, c.byref(dev), 1, idx, c.byref(drv)):
                if c.get_last_error() != 259:
                    raise c.WinError(c.get_last_error())
                break
            candidates.append(drv.description)
            if "RNDIS6" in drv.description or "NDIS 6" in drv.description:
                chosen = drv
            elif chosen is None:
                chosen = drv
            idx += 1
        if chosen is None:
            raise RuntimeError("No Microsoft inbox RNDIS driver model found")
        result: dict[str, Any] = {"instance_id": ids[0], "candidates": candidates}
        if install:
            chk(setup.SetupDiSetSelectedDriverW(handle, c.byref(dev), c.byref(chosen)))
            reboot = c.c_int()
            chk(newdev.DiInstallDevice(None, handle, c.byref(dev), c.byref(chosen), 0x2, c.byref(reboot)))
            result["bound"] = chosen.description
            result["reboot_needed"] = bool(reboot.value)
        return result
    finally:
        setup.SetupDiDestroyDeviceInfoList(handle)


def _walk_linux_sysfs_usb_ids(device_dir: Path) -> dict[str, str]:
    """Walk up Linux /sys/class/net/<iface>/device parent chain to read USB idVendor/idProduct/serial/port_path."""
    cur = device_dir.resolve()
    for _ in range(5):
        vid_f = cur / "idVendor"
        pid_f = cur / "idProduct"
        if vid_f.is_file() and pid_f.is_file():
            ser_f = cur / "serial"
            prod_f = cur / "product"
            return {
                "vid": vid_f.read_text(encoding="utf-8", errors="ignore").strip().lower(),
                "pid": pid_f.read_text(encoding="utf-8", errors="ignore").strip().lower(),
                "serial": ser_f.read_text(encoding="utf-8", errors="ignore").strip() if ser_f.is_file() else "",
                "product": prod_f.read_text(encoding="utf-8", errors="ignore").strip() if prod_f.is_file() else "",
                "port_path": cur.name,
            }
        if cur.parent == cur:
            break
        cur = cur.parent
    return {}


def _detect_linux_net_candidates(net_root: Path = Path("/sys/class/net")) -> list[dict[str, Any]]:
    """Enumerate Linux network interfaces with exact USB VID/PID/serial/port_path metadata."""
    cands: list[dict[str, Any]] = []
    if not net_root.is_dir():
        return cands
    for entry in sorted(net_root.iterdir()):
        name = entry.name
        if name == "lo":
            continue
        dev_link = entry / "device"
        if not dev_link.exists():
            continue
        meta = _walk_linux_sysfs_usb_ids(dev_link)
        cands.append({"name": name, "device": name, **meta})
    return cands


def parse_linux_ip_routes(v4_json: str, v6_json: str, usb_iface_names: set[str]) -> dict[str, Any]:
    """Parse Linux `ip -j route show default` JSON outputs and flag default routes via correlated F50 interfaces ONLY."""
    v4 = json.loads(v4_json) if v4_json.strip() else []
    v6 = json.loads(v6_json) if v6_json.strip() else []
    leaks = [r for r in v4 + v6 if r.get("dev") in usb_iface_names]
    return {
        "host_platform": "linux",
        "ipv4_default": v4,
        "ipv6_default": v6,
        "usb_default_route_leak": bool(leaks),
        "leaks": leaks,
    }


def parse_macos_hardware_ports(ports_output: str) -> list[dict[str, str]]:
    """Parse `networksetup -listallhardwareports` into {hardware_port, device, mac} dicts."""
    ports: list[dict[str, str]] = []
    cur: dict[str, str] = {}
    for line in ports_output.splitlines():
        line = line.strip()
        if not line:
            if cur:
                ports.append(cur)
                cur = {}
            continue
        if line.startswith("Hardware Port:"):
            if cur:
                ports.append(cur)
                cur = {}
            hp_val = line.split(":", 1)[1].strip()
            cur["port"] = hp_val
            cur["hardware_port"] = hp_val
        elif line.startswith("Device:"):
            cur["device"] = line.split(":", 1)[1].strip()
        elif line.startswith("Ethernet Address:"):
            cur["mac"] = line.split(":", 1)[1].strip()
    if cur:
        ports.append(cur)
    return ports


def parse_macos_network_service_order(order_output: str) -> list[dict[str, Any]]:
    """Parse `networksetup -listnetworkserviceorder` distinguishing Network Service vs Hardware Port vs BSD Device."""
    services: list[dict[str, Any]] = []
    cur_svc: dict[str, Any] | None = None
    for raw in order_output.splitlines():
        line = raw.strip()
        m_svc = re.match(r"^\((\d+|\*)\)\s+(.+)$", line)
        if m_svc and not line.startswith("(Hardware Port:"):
            cur_svc = {
                "network_service": m_svc.group(2).strip(),
                "enabled": m_svc.group(1) != "*",
                "order": None if m_svc.group(1) == "*" else int(m_svc.group(1)),
            }
            continue
        m_hw = re.match(r"^\(Hardware Port:\s*(.+?),\s*Device:\s*([^)]+)\)$", line)
        if m_hw and cur_svc is not None:
            cur_svc["hardware_port"] = m_hw.group(1).strip()
            cur_svc["device"] = m_hw.group(2).strip()
            cur_svc["name"] = cur_svc["device"]
            services.append(cur_svc)
            cur_svc = None
    return services


def parse_macos_spusb_net_devices(spusb_json: str) -> list[dict[str, str]]:
    """Extract USB VID/PID/serial/location_id/BSD names from `system_profiler SPUSBDataType -json`."""
    found: list[dict[str, str]] = []
    try:
        data = json.loads(spusb_json or "{}")
    except json.JSONDecodeError:
        return found

    def _walk(node: Any) -> None:
        if isinstance(node, list):
            for x in node:
                _walk(x)
            return
        if not isinstance(node, dict):
            return
        vid_raw = str(node.get("vendor_id", ""))
        pid_raw = str(node.get("product_id", ""))
        m_vid = re.search(r"0x([0-9a-fA-F]{4})", vid_raw)
        m_pid = re.search(r"0x([0-9a-fA-F]{4})", pid_raw)
        vid = m_vid.group(1).lower() if m_vid else vid_raw.lower()
        pid = m_pid.group(1).lower() if m_pid else pid_raw.lower()
        bsd = str(node.get("bsd_name", "") or node.get("BSD Name", ""))
        # Also look inside Media / Ethernet dicts if present
        if not bsd:
            for k, v in node.items():
                if isinstance(v, dict) and v.get("bsd_name"):
                    bsd = str(v["bsd_name"])
        if vid or pid:
            found.append(
                {
                    "vid": vid,
                    "pid": pid,
                    "serial": str(node.get("serial_num", "")),
                    "port_path": str(node.get("location_id", "")),
                    "device": bsd,
                    "product": str(node.get("_name", "")),
                }
            )
        if "_items" in node:
            _walk(node["_items"])

    _walk(data.get("SPUSBDataType", []))
    return found


def correlate_macos_net_candidates(
    services: list[dict[str, Any]],
    spusb_items: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """Correlate macOS Network Service + Hardware Port + BSD enX with SPUSB USB VID/PID/serial."""
    by_bsd = {u["device"]: u for u in spusb_items if u.get("device")}
    merged: list[dict[str, Any]] = []
    for svc in services:
        dev = svc.get("device", "")
        u = by_bsd.get(dev, {})
        merged.append(
            {
                **svc,
                "vid": u.get("vid", ""),
                "pid": u.get("pid", ""),
                "serial": u.get("serial", ""),
                "port_path": u.get("port_path", ""),
                "product": u.get("product", ""),
            }
        )
    return merged


def _parse_macos_default_lines(netstat_output: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for raw in netstat_output.splitlines():
        parts = raw.split()
        if len(parts) >= 4 and parts[0] == "default":
            out.append({"destination": parts[0], "gateway": parts[1], "flags": parts[2], "netif": parts[-1]})
    return out


def parse_macos_netstat_routes(v4_text: str, v6_text: str, target_bsd_devs: set[str]) -> dict[str, Any]:
    """Parse macOS `netstat -rn` tables and flag default gateway routes via correlated F50 BSD interfaces ONLY."""
    r4 = _parse_macos_default_lines(v4_text)
    r6 = _parse_macos_default_lines(v6_text)
    leaks = [r for r in r4 + r6 if r.get("netif") in target_bsd_devs]
    return {
        "host_platform": "macos",
        "ipv4_default": r4,
        "ipv6_default": r6,
        "usb_default_route_leak": bool(leaks),
        "leaks": leaks,
    }


def _detect_macos_candidates() -> list[dict[str, Any]]:
    ord_res = _run_cmd(["networksetup", "-listnetworkserviceorder"], check=False)
    svcs = parse_macos_network_service_order(ord_res.stdout) if ord_res.returncode == 0 else []
    usb_res = _run_cmd(["system_profiler", "SPUSBDataType", "-json"], check=False)
    spusb = parse_macos_spusb_net_devices(usb_res.stdout) if usb_res.returncode == 0 else []
    return correlate_macos_net_candidates(svcs, spusb)


def _snapshot_linux_iface(ifname: str) -> dict[str, Any]:
    addr_res = _run_cmd(["ip", "-j", "addr", "show", "dev", ifname], check=False)
    addrs = json.loads(addr_res.stdout) if addr_res.returncode == 0 and addr_res.stdout.strip() else []
    nm_conn = ""
    nm_state: dict[str, str] = {}
    nmcli = shutil.which("nmcli")
    if nmcli:
        c_res = _run_cmd([nmcli, "-g", "GENERAL.CONNECTION", "dev", "show", ifname], check=False)
        nm_conn = c_res.stdout.strip() if c_res.returncode == 0 else ""
        if nm_conn and nm_conn != "--":
            for k in ("ipv4.method", "ipv4.addresses", "ipv4.gateway", "ipv4.never-default", "ipv6.method"):
                v_res = _run_cmd([nmcli, "-g", k, "con", "show", nm_conn], check=False)
                nm_state[k] = v_res.stdout.strip()
    return {
        "platform": "linux",
        "iface": ifname,
        "ip_addr_json": addrs,
        "nm_connection": nm_conn,
        "nm_state": nm_state,
    }


def _snapshot_macos_service(svc: str, dev: str) -> dict[str, Any]:
    info_res = _run_cmd(["networksetup", "-getinfo", svc], check=False)
    dns_res = _run_cmd(["networksetup", "-getdnsservers", svc], check=False)
    return {
        "platform": "macos",
        "network_service": svc,
        "device": dev,
        "getinfo": info_res.stdout.strip(),
        "getdnsservers": dns_res.stdout.strip(),
    }


def _snapshot_windows_adapter(iface_name: str) -> dict[str, Any]:
    raw = _ps(
        f"$ad = Get-NetAdapter -Name '{iface_name}' -ErrorAction SilentlyContinue; "
        "if ($ad) { "
        "$ips = @(Get-NetIPAddress -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object IPAddress,PrefixLength,PrefixOrigin); "
        "$dns = (Get-DnsClientServerAddress -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses; "
        "$v6 = (Get-NetAdapterBinding -Name $ad.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue).Enabled; "
        "@{ name = $ad.Name; ifIndex = $ad.ifIndex; ips = $ips; dns = @($dns); ipv6_enabled = $v6 } | ConvertTo-Json -Depth 4 -Compress }"
    )
    return {"platform": "win64", **json.loads(raw)} if raw else {"platform": "win64", "name": iface_name}


def restore_network_snapshot(snapshot_path: Path, *, force: bool = False) -> dict[str, Any]:
    """Restore pre-isolation network settings ONLY if current state still matches what we applied (or force=True)."""
    snap = read_json(snapshot_path)
    results: list[dict[str, Any]] = []
    for entry in snap.get("entries", []):
        applied_ip = snap.get("applied_static_ip", "192.168.77.12")
        plat = entry.get("platform")
        if plat == "linux":
            ifname = entry["iface"]
            cur = _snapshot_linux_iface(ifname)
            cur_ips = [ai.get("local") for blk in cur.get("ip_addr_json", []) for ai in blk.get("addr_info", [])]
            if not force and cur_ips != [applied_ip]:
                results.append({"iface": ifname, "status": "skipped_user_modified", "live_ips": cur_ips})
                continue
            nmcli = shutil.which("nmcli")
            conn = entry.get("nm_connection", "")
            nm = entry.get("nm_state", {})
            if nmcli and conn and nm:
                _run_priv_posix(
                    [
                        nmcli,
                        "con",
                        "mod",
                        conn,
                        "ipv4.method",
                        nm.get("ipv4.method") or "auto",
                        "ipv4.addresses",
                        nm.get("ipv4.addresses", ""),
                        "ipv4.gateway",
                        nm.get("ipv4.gateway", ""),
                        "ipv4.never-default",
                        nm.get("ipv4.never-default") or "no",
                        "ipv6.method",
                        nm.get("ipv6.method") or "auto",
                    ]
                )
                _run_priv_posix([nmcli, "dev", "reapply", ifname], check=False)
                results.append({"iface": ifname, "status": "restored_nmcli"})
            else:
                _run_priv_posix(["ip", "addr", "flush", "dev", ifname], check=False)
                results.append({"iface": ifname, "status": "flushed_ip"})
        elif plat == "macos":
            svc = entry["network_service"]
            cur = _snapshot_macos_service(svc, entry["device"])
            if not force and f"IP address: {applied_ip}" not in cur.get("getinfo", ""):
                results.append({"network_service": svc, "status": "skipped_user_modified"})
                continue
            _run_priv_posix(["networksetup", "-setdhcp", svc])
            _run_priv_posix(["networksetup", "-setv6automatic", svc], check=False)
            results.append({"network_service": svc, "status": "restored_dhcp"})
        elif plat == "win64":
            name = entry["name"]
            cur = _snapshot_windows_adapter(name)
            live_ips = [x.get("IPAddress") for x in cur.get("ips", [])]
            if not force and live_ips != [applied_ip]:
                results.append({"iface": name, "status": "skipped_user_modified", "live_ips": live_ips})
                continue
            _ps(
                f"Set-NetIPInterface -InterfaceAlias '{name}' -AddressFamily IPv4 -Dhcp Enabled -AutomaticMetric Enabled -ErrorAction SilentlyContinue; "
                f"Enable-NetAdapterBinding -Name '{name}' -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue"
            )
            results.append({"iface": name, "status": "restored_dhcp"})
    return {"snapshot_path": str(snapshot_path), "results": results}


def isolate_usb_rndis_adapter(
    static_ip: str = "192.168.77.12",
    *,
    mode: str = "management",
    target_iface: str | None = None,
    usb_topology: dict[str, Any] | None = None,
    include_zte_android: bool = False,
    snapshot_path: Path | None = None,
) -> dict[str, Any]:
    """Configure ONLY the correlated F50 Pro USB interface (`management` LAN-only vs explicit `internet-exit`)."""
    if mode not in ("management", "internet-exit"):
        raise ValueError(f"Unsupported host network mode {mode!r}; expected 'management' or 'internet-exit'")

    plat = detect_host_platform()
    if mode == "internet-exit":
        return {
            "host_platform": plat,
            "mode": "internet-exit",
            "isolated": [],
            "note": "Internet-exit mode requested explicitly; leaving target F50 Pro DHCP/default gateway active.",
        }

    if plat == "win64":
        cand_raw = _ps(
            "$ads = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } "
            "| ForEach-Object { @{ name = $_.Name; ifIndex = $_.ifIndex; desc = $_.InterfaceDescription; pnp_id = $_.PnpDeviceID; "
            "vid = if ($_.PnpDeviceID -match 'VID_([0-9A-Fa-f]{4})') { $Matches[1].ToLower() } else { '' }; "
            "pid = if ($_.PnpDeviceID -match 'PID_([0-9A-Fa-f]{4})') { $Matches[1].ToLower() } else { '' }; "
            "serial = if ($_.PnpDeviceID -match '\\\\([^\\\\]+)$') { $Matches[1] } else { '' } } }); "
            "$ads | ConvertTo-Json -Depth 4 -Compress"
        )
        cands = json.loads(cand_raw) if cand_raw else []
        if isinstance(cands, dict):
            cands = [cands]
        sel = select_target_usb_adapters(
            cands,
            target_iface=target_iface,
            usb_topology=usb_topology,
            include_zte_android=include_zte_android,
        )
        if sel["ambiguous"]:
            raise RuntimeError(f"Multiple correlated F50 Pro adapters found on Windows without disambiguation: {sel['targets']}")
        targets = sel["targets"]
        if not targets:
            return {"host_platform": "win64", "mode": mode, "isolated": [], "ignored": sel["ignored"], "status": "no_target_matched"}

        snapshots = [_snapshot_windows_adapter(t["name"]) for t in targets]
        if snapshot_path is not None:
            write_json(
                snapshot_path,
                {
                    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "applied_static_ip": static_ip,
                    "entries": snapshots,
                },
            )

        target_names = [t["name"] for t in targets]
        names_ps = ",".join(f"'{n}'" for n in target_names)
        ps_script = f"""
$ErrorActionPreference = 'Stop'
$ads = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -in @({names_ps}) }}
$updated = @()
foreach ($ad in $ads) {{
    $reg = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$($ad.InterfaceGuid)"
    if (Test-Path $reg) {{
        Set-ItemProperty -Path $reg -Name EnableDHCP -Value 0 -Type DWord
        Set-ItemProperty -Path $reg -Name IPAddress -Value ([string[]]@('{static_ip}')) -Type MultiString
        Set-ItemProperty -Path $reg -Name SubnetMask -Value ([string[]]@('255.255.255.0')) -Type MultiString
        Set-ItemProperty -Path $reg -Name DefaultGateway -Value ([string[]]@()) -Type MultiString
        Set-ItemProperty -Path $reg -Name NameServer -Value '' -Type String
        Remove-ItemProperty -Path $reg -Name DhcpDefaultGateway -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $reg -Name DhcpNameServer -ErrorAction SilentlyContinue
    }}
    Disable-NetAdapterBinding -Name $ad.Name -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue
    Set-NetIPInterface -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -Dhcp Disabled -AutomaticMetric Disabled -InterfaceMetric 5000 -ErrorAction SilentlyContinue
    Get-NetIPAddress -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {{ $_.IPAddress -ne '{static_ip}' }} | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    if (-not (Get-NetIPAddress -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {{ $_.IPAddress -eq '{static_ip}' }})) {{
        New-NetIPAddress -InterfaceIndex $ad.ifIndex -IPAddress '{static_ip}' -PrefixLength 24 -Confirm:$false | Out-Null
    }}
    Set-DnsClientServerAddress -InterfaceIndex $ad.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
    Set-DnsClient -InterfaceIndex $ad.ifIndex -RegisterThisConnectionsAddress $false -ErrorAction SilentlyContinue
    Get-NetRoute -InterfaceIndex $ad.ifIndex -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    $updated += @{{ name = $ad.Name; ifIndex = $ad.ifIndex; pnp_id = $ad.PnpDeviceID; ip = '{static_ip}' }}
}}
Start-Sleep -Seconds 2
$targetIdx = @($ads | ForEach-Object {{ $_.ifIndex }})
$routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue | Where-Object {{ $_.ifIndex -in $targetIdx }} | Select-Object ifIndex,InterfaceAlias,NextHop,RouteMetric)
@{{ isolated = $updated; target_default_routes = $routes }} | ConvertTo-Json -Depth 4 -Compress
"""
        raw = _ps(ps_script)
        data = json.loads(raw) if raw else {"isolated": [], "target_default_routes": []}
        if data.get("target_default_routes"):
            raise RuntimeError(f"Default gateway leak persists on correlated F50 Pro adapter: {data['target_default_routes']}")
        data["ignored"] = sel["ignored"]
        return data

    if plat in ("linux-x64", "linux-arm64"):
        cands = _detect_linux_net_candidates()
        sel = select_target_usb_adapters(
            cands,
            target_iface=target_iface,
            usb_topology=usb_topology,
            include_zte_android=include_zte_android,
        )
        if sel["ambiguous"]:
            raise RuntimeError(f"Multiple correlated F50 Pro USB interfaces on Linux without disambiguation: {sel['targets']}")
        targets = sel["targets"]
        if not targets:
            return {"host_platform": plat, "mode": mode, "isolated": [], "ignored": sel["ignored"], "status": "no_target_matched"}

        snapshots = [_snapshot_linux_iface(t["name"]) for t in targets]
        if snapshot_path is not None:
            write_json(
                snapshot_path,
                {
                    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "applied_static_ip": static_ip,
                    "entries": snapshots,
                },
            )

        updated: list[dict[str, Any]] = []
        nmcli = shutil.which("nmcli")
        for item in targets:
            ifname = item["name"]
            if nmcli:
                con_res = _run_cmd([nmcli, "-g", "GENERAL.CONNECTION", "dev", "show", ifname], check=False)
                conn = con_res.stdout.strip()
                if conn and conn != "--":
                    _run_priv_posix(
                        [
                            nmcli,
                            "con",
                            "mod",
                            conn,
                            "ipv4.method",
                            "manual",
                            "ipv4.addresses",
                            f"{static_ip}/24",
                            "ipv4.gateway",
                            "",
                            "ipv4.never-default",
                            "yes",
                            "ipv4.ignore-auto-dns",
                            "yes",
                            "ipv6.method",
                            "disabled",
                        ]
                    )
                    _run_priv_posix([nmcli, "dev", "reapply", ifname], check=False)
                    updated.append({"name": ifname, "method": "nmcli", "connection": conn, "ip": static_ip})
                    continue
            _run_priv_posix(["ip", "addr", "replace", f"{static_ip}/24", "dev", ifname])
            _run_priv_posix(["ip", "route", "del", "default", "dev", ifname], check=False)
            _run_priv_posix(["ip", "-6", "route", "del", "default", "dev", ifname], check=False)
            updated.append({"name": ifname, "method": "iproute2", "ip": static_ip})

        audit = audit_default_routes(target_iface=target_iface, usb_topology=usb_topology, include_zte_android=include_zte_android)
        if audit.get("usb_default_route_leak"):
            raise RuntimeError(f"Linux default gateway leak persists after isolation: {audit['leaks']}")
        return {"host_platform": plat, "mode": mode, "isolated": updated, "ignored": sel["ignored"], "audit": audit}

    if plat == "macos":
        cands = _detect_macos_candidates()
        sel = select_target_usb_adapters(
            cands,
            target_iface=target_iface,
            usb_topology=usb_topology,
            include_zte_android=include_zte_android,
        )
        if sel["ambiguous"]:
            raise RuntimeError(f"Multiple correlated F50 Pro USB services on macOS without disambiguation: {sel['targets']}")
        targets = sel["targets"]
        if not targets:
            return {"host_platform": "macos", "mode": mode, "isolated": [], "ignored": sel["ignored"], "status": "no_target_matched"}

        snapshots = [_snapshot_macos_service(t["network_service"], t["device"]) for t in targets]
        if snapshot_path is not None:
            write_json(
                snapshot_path,
                {
                    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "applied_static_ip": static_ip,
                    "entries": snapshots,
                },
            )

        updated = []
        for item in targets:
            svc = item["network_service"]
            dev = item["device"]
            _run_priv_posix(["networksetup", "-setmanual", svc, static_ip, "255.255.255.0", ""])
            _run_priv_posix(["networksetup", "-setdnsservers", svc, "Empty"])
            _run_priv_posix(["networksetup", "-setv6off", svc], check=False)
            _run_priv_posix(["route", "-n", "delete", "default", "-ifscope", dev], check=False)
            updated.append({"network_service": svc, "hardware_port": item.get("hardware_port"), "device": dev, "ip": static_ip})
        audit = audit_default_routes(target_iface=target_iface, usb_topology=usb_topology, include_zte_android=include_zte_android)
        if audit.get("usb_default_route_leak"):
            raise RuntimeError(f"macOS default gateway leak persists after isolation: {audit['leaks']}")
        return {"host_platform": "macos", "mode": mode, "isolated": updated, "ignored": sel["ignored"], "audit": audit}

    return {
        "host_platform": plat,
        "skipped": "android-host",
        "note": "Android manages USB tethering/Ethernet routes inside ConnectivityService; disable mobile/Wi-Fi clash when provisioning over SSH.",
    }


def audit_default_routes(
    *,
    target_iface: str | None = None,
    usb_topology: dict[str, Any] | None = None,
    include_zte_android: bool = False,
) -> dict[str, Any]:
    """Read-only verification that 0.0.0.0/0 and ::/0 do not route via correlated F50 Pro USB interface(s)."""
    if sys.platform == "win32":
        raw = _ps(
            "$r4 = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object ifIndex,InterfaceAlias,NextHop,RouteMetric);"
            "$r6 = @(Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Select-Object ifIndex,InterfaceAlias,NextHop,RouteMetric);"
            "$usb = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.PnpDeviceID -match 'VID_1D6B&PID_0104' } | Select-Object ifIndex,Name,InterfaceDescription,PnpDeviceID,Status);"
            "@{ ipv4_default = $r4; ipv6_default = $r6; rndis_adapters = $usb } | ConvertTo-Json -Depth 4 -Compress"
        )
        info = json.loads(raw)
        cands = info.get("rndis_adapters", [])
        if target_iface:
            cands = [a for a in cands if a.get("Name") == target_iface]
        usb_indices = {a["ifIndex"] for a in cands}
        # Only count default routes actually egressing an identified F50 Pro interface (NOT normal Wi-Fi on 192.168.0.1!)
        leaks = [
            r
            for r in info.get("ipv4_default", []) + info.get("ipv6_default", [])
            if r.get("ifIndex") in usb_indices
        ]
        info["host_platform"] = "win64"
        info["usb_default_route_leak"] = bool(leaks)
        info["leaks"] = leaks
        return info

    plat = detect_host_platform()
    if plat in ("linux-x64", "linux-arm64"):
        cands = _detect_linux_net_candidates()
        sel = select_target_usb_adapters(
            cands,
            target_iface=target_iface,
            usb_topology=usb_topology,
            include_zte_android=include_zte_android,
        )
        target_names = {x["name"] for x in sel["targets"]}
        if not shutil.which("ip"):
            return {
                "host_platform": plat,
                "usb_default_route_leak": False,
                "usb_adapters": sel["targets"],
                "ambiguous": sel["ambiguous"],
                "warning": "ip command missing",
            }
        r4 = _run_cmd(["ip", "-j", "route", "show", "default"], check=False)
        r6 = _run_cmd(["ip", "-j", "-6", "route", "show", "default"], check=False)
        info = parse_linux_ip_routes(r4.stdout if r4.returncode == 0 else "[]", r6.stdout if r6.returncode == 0 else "[]", target_names)
        info["host_platform"] = plat
        info["usb_adapters"] = sel["targets"]
        info["ambiguous"] = sel["ambiguous"]
        info["ignored_non_target_ifaces"] = sel["ignored"]
        return info

    if plat == "macos":
        cands = _detect_macos_candidates()
        sel = select_target_usb_adapters(
            cands,
            target_iface=target_iface,
            usb_topology=usb_topology,
            include_zte_android=include_zte_android,
        )
        target_devs = {x["device"] for x in sel["targets"] if x.get("device")}
        r4 = _run_cmd(["netstat", "-rn", "-f", "inet"], check=False)
        r6 = _run_cmd(["netstat", "-rn", "-f", "inet6"], check=False)
        info = parse_macos_netstat_routes(r4.stdout, r6.stdout, target_devs)
        info["usb_adapters"] = sel["targets"]
        info["ambiguous"] = sel["ambiguous"]
        info["ignored_non_target_services"] = sel["ignored"]
        return info

    # Android host (Termux / rooted phone): read-only check without falsely claiming 192.168.0.1 Wi-Fi is a leak
    routes_txt = ""
    if shutil.which("ip"):
        res = _run_cmd(["ip", "route", "show", "default"], check=False)
        if res.returncode == 0:
            routes_txt = res.stdout.strip()
    leak = "192.168.77." in routes_txt
    return {
        "host_platform": plat,
        "rooted": bool(hasattr(os, "geteuid") and os.geteuid() == 0),
        "default_routes_text": routes_txt,
        "usb_default_route_leak": leak,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_aud = sub.add_parser("audit", help="Verify host default gateway does not traverse correlated F50 Pro USB interface")
    p_aud.add_argument("--target-iface")
    sub.add_parser("bind-rndis", help="Bind Windows RNDIS6 driver (no-op on POSIX)")
    p_iso = sub.add_parser("isolate", help="Isolate correlated F50 Pro USB adapter to static management IP only")
    p_iso.add_argument("--ip", default="192.168.77.12")
    p_iso.add_argument("--mode", default="management", choices=["management", "internet-exit"])
    p_iso.add_argument("--target-iface")
    p_iso.add_argument("--snapshot", type=Path)
    p_res = sub.add_parser("restore", help="Restore saved network snapshot (refuses overwriting user changes unless --force)")
    p_res.add_argument("--snapshot", type=Path, required=True)
    p_res.add_argument("--force", action="store_true")
    args = parser.parse_args()

    if args.cmd == "audit":
        res = audit_default_routes(target_iface=args.target_iface)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 1 if res.get("usb_default_route_leak") else 0
    if args.cmd == "bind-rndis":
        clear_negative_usbflags_rndis()
        res = bind_inbox_rndis_driver(install=True)
        time.sleep(2)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0
    if args.cmd == "restore":
        res = restore_network_snapshot(args.snapshot, force=args.force)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0
    res = isolate_usb_rndis_adapter(
        static_ip=args.ip,
        mode=args.mode,
        target_iface=args.target_iface,
        snapshot_path=args.snapshot,
    )
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
