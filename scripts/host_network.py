"""Cross-platform targeted F50 Pro USB network isolation, snapshot restore, and strict default-route auditing."""
from __future__ import annotations

import argparse
import base64
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


_PS_SMART_QUOTES = ("\u2018", "\u2019", "\u201a", "\u201b")


def _ps_quote(val: str) -> str:
    """Safely quote an arbitrary string for Windows PowerShell 5.1/7 (immune to ASCII & smart quotes)."""
    text = str(val)
    if any(ch in text for ch in _PS_SMART_QUOTES) or any(ord(ch) < 0x20 for ch in text):
        b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
        return f"([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64}')))"
    return "'" + text.replace("'", "''") + "'"


def _ps(cmd: str, *, timeout: float = 30.0) -> str:
    wrapped = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); " + cmd
    res = subprocess.run(
        ["powershell", "-NoProfile", "-Command", wrapped],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
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

    # Disambiguation succeeded only when at most 1 candidate remains; missing serial/port_path must never bypass ambiguity.
    ambiguous = len(matched) > 1
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
            for k in (
                "ipv4.method",
                "ipv4.addresses",
                "ipv4.gateway",
                "ipv4.never-default",
                "ipv4.ignore-auto-dns",
                "ipv6.method",
            ):
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
    q_name = _ps_quote(iface_name)
    raw = _ps(
        f"$ad = Get-NetAdapter -Name {q_name} -ErrorAction SilentlyContinue; "
        "if ($ad) { "
        "$ifv4 = Get-NetIPInterface -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue; "
        "$ips = @(Get-NetIPAddress -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object IPAddress,PrefixLength,PrefixOrigin); "
        "$gws = @(Get-NetRoute -InterfaceIndex $ad.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NextHop); "
        "$dns = (Get-DnsClientServerAddress -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses; "
        "$reg = \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$($ad.InterfaceGuid)\"; "
        "$ns = if (Test-Path $reg) { (Get-ItemProperty -Path $reg -Name NameServer -ErrorAction SilentlyContinue).NameServer } else { '' }; "
        "$staticDns = if ($ns) { @($ns -split '[,\\s]+' | Where-Object { $_ }) } else { @() }; "
        "$v6 = (Get-NetAdapterBinding -Name $ad.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue).Enabled; "
        "$regDns = (Get-DnsClient -InterfaceIndex $ad.ifIndex -ErrorAction SilentlyContinue).RegisterThisConnectionsAddress; "
        "@{ name = $ad.Name; ifIndex = $ad.ifIndex; pnp_id = $ad.PnpDeviceID; status = [string]$ad.Status; dhcp = ($ifv4.Dhcp -eq 'Enabled'); ips = $ips; gateways = $gws; dns = @($dns); static_dns = $staticDns; ipv6_enabled = $v6; register_dns = $regDns } | ConvertTo-Json -Depth 4 -Compress }"
    )
    return {"platform": "win64", **json.loads(raw)} if raw else {"platform": "win64", "name": iface_name}


def _snapshot_entry_key(entry: dict[str, Any]) -> tuple[str, str]:
    plat = str(entry.get("platform") or "")
    ident = str(entry.get("name") or entry.get("iface") or entry.get("network_service") or "")
    return (plat, ident)


def _save_initial_snapshot(
    snapshot_path: Path | None,
    applied_static_ip: str,
    new_entries: list[dict[str, Any]],
) -> None:
    """Persist pre-isolation snapshot without overwriting already-captured adapter baselines on reconnects."""
    if snapshot_path is None:
        return
    merged_entries: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str]] = set()
    created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if snapshot_path.is_file():
        try:
            existing = read_json(snapshot_path)
            if isinstance(existing, dict) and isinstance(existing.get("entries"), list):
                created_at = str(existing.get("created_at") or created_at)
                for item in existing["entries"]:
                    if isinstance(item, dict):
                        key = _snapshot_entry_key(item)
                        if key not in seen_keys:
                            seen_keys.add(key)
                            merged_entries.append(item)
        except Exception:
            pass
    for item in new_entries:
        key = _snapshot_entry_key(item)
        if key not in seen_keys:
            seen_keys.add(key)
            merged_entries.append(item)
    write_json(
        snapshot_path,
        {
            "created_at": created_at,
            "applied_static_ip": applied_static_ip,
            "entries": merged_entries,
        },
    )


def _check_windows_f50_usb_disconnected() -> dict[str, Any]:
    """Fail-closed live PnP check verifying no F50 Pro USB device (OpenWrt or Stock Android) is connected on Windows."""
    live_usb_raw = _ps(
        "$ok = $true; $hits = @(); "
        "try { $hits = @(Get-CimInstance Win32_PnPEntity -ErrorAction Stop | "
        "Where-Object { $_.PNPDeviceID -match 'VID_1D6B&PID_0104|VID_19D2&PID_024' } | "
        "Select-Object -ExpandProperty PNPDeviceID) } catch { $ok = $false }; "
        "@{ query_ok = $ok; connected_count = $hits.Count } | ConvertTo-Json -Compress"
    )
    try:
        parsed = json.loads(live_usb_raw) if live_usb_raw else {"query_ok": False, "connected_count": 0}
        return parsed if isinstance(parsed, dict) else {"query_ok": False, "connected_count": 0}
    except Exception:
        return {"query_ok": False, "connected_count": 0}


def restore_network_snapshot(
    snapshot_path: Path,
    *,
    force: bool = False,
    target_names: set[str] | None = None,
) -> dict[str, Any]:
    """Restore pre-isolation network settings ONLY if current state still matches what we applied (or force=True)."""
    snap = read_json(snapshot_path)
    results: list[dict[str, Any]] = []
    for entry in snap.get("entries", []):
        applied_ip = snap.get("applied_static_ip", "192.168.77.12")
        plat = entry.get("platform")
        ident = entry.get("name") or entry.get("iface") or entry.get("network_service")
        if target_names is not None and ident not in target_names:
            continue
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
                        "ipv4.ignore-auto-dns",
                        nm.get("ipv4.ignore-auto-dns") or "no",
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
            orig_info = entry.get("getinfo", "")
            if "Manual Configuration" in orig_info:
                m_ip = re.search(r"^IP address:\s*(\S+)", orig_info, re.M)
                m_mask = re.search(r"^Subnet mask:\s*(\S+)", orig_info, re.M)
                m_gw = re.search(r"^Router:\s*(\S+)", orig_info, re.M)
                if m_ip and m_mask:
                    gw = m_gw.group(1) if m_gw and m_gw.group(1) != "(null)" else ""
                    _run_priv_posix(["networksetup", "-setmanual", svc, m_ip.group(1), m_mask.group(1), gw])
                else:
                    _run_priv_posix(["networksetup", "-setdhcp", svc])
            else:
                _run_priv_posix(["networksetup", "-setdhcp", svc])
            orig_dns = [ln.strip() for ln in entry.get("getdnsservers", "").splitlines() if ln.strip()]
            if orig_dns and not orig_dns[0].lower().startswith("there aren't"):
                _run_priv_posix(["networksetup", "-setdnsservers", svc, *orig_dns], check=False)
            else:
                _run_priv_posix(["networksetup", "-setdnsservers", svc, "Empty"], check=False)
            if "IPv6: Off" in orig_info:
                _run_priv_posix(["networksetup", "-setv6off", svc], check=False)
            else:
                _run_priv_posix(["networksetup", "-setv6automatic", svc], check=False)
            results.append({"network_service": svc, "status": "restored_macos"})
        elif plat == "win64":
            name = entry["name"]
            # Always enforce live USB disconnect gate on Windows EVEN when force=True so forced restore
            # can never release host management isolation while F50 Pro is still plugged in!
            usb_chk = _check_windows_f50_usb_disconnected()
            if not usb_chk.get("query_ok"):
                raise RuntimeError(
                    "Refusing to restore Windows network snapshot because live USB PnP safety check failed "
                    "(unplug F50 Pro and verify Windows CIM/PnP health before retrying)."
                )
            if int(usb_chk.get("connected_count") or 0) > 0:
                raise RuntimeError(
                    "Refusing to restore Windows DHCP/gateway snapshot while F50 Pro USB device is still connected "
                    "(unplug the F50 Pro USB cable first to prevent host route leak)."
                )
            cur = _snapshot_windows_adapter(name)
            snap_pnp = str(entry.get("pnp_id") or "").upper()
            cur_pnp = str(cur.get("pnp_id") or "").upper()
            if not force and snap_pnp and cur_pnp and snap_pnp != cur_pnp:
                results.append({"iface": name, "status": "skipped_pnp_mismatch"})
                continue
            live_ips = [x.get("IPAddress") for x in cur.get("ips", [])]
            if not force and live_ips != [applied_ip]:
                results.append({"iface": name, "status": "skipped_user_modified", "live_ips": live_ips})
                continue
            q_name = _ps_quote(name)
            was_dhcp = entry.get("dhcp")
            orig_ips = entry.get("ips") or []
            if was_dhcp is None:
                was_dhcp = not any(str(x.get("PrefixOrigin", "")).lower() == "manual" for x in orig_ips)
            v6_enabled = entry.get("ipv6_enabled", True)
            reg_dns = entry.get("register_dns", True)
            orig_static_dns = [d for d in (entry.get("static_dns") or []) if d]
            orig_dns = [d for d in (entry.get("dns") or []) if d]
            # For DHCP adapters, only apply explicit static_dns overrides (never pin DHCP-leased DNS as static).
            dns_to_set = orig_static_dns if was_dhcp else (orig_static_dns or orig_dns)
            orig_gws = [g for g in (entry.get("gateways") or []) if g and g != "0.0.0.0"]

            ps_lines = [
                "$errs = @()",
                f"$ad = Get-NetAdapter -Name {q_name} -ErrorAction SilentlyContinue",
                "if (-not $ad) { @{ found = $false; errors = @('adapter_not_found') } | ConvertTo-Json -Compress } else {",
                "  $reg = \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$($ad.InterfaceGuid)\"",
            ]
            if was_dhcp:
                ps_lines.extend([
                    "  if (Test-Path $reg) {",
                    "    try { Set-ItemProperty -Path $reg -Name EnableDHCP -Value 1 -Type DWord -ErrorAction Stop } catch { $errs += $_.Exception.Message }",
                    "    Remove-ItemProperty -Path $reg -Name IPAddress,SubnetMask,DefaultGateway,NameServer -ErrorAction SilentlyContinue",
                    "  }",
                    "  Get-NetIPAddress -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.PrefixOrigin -eq 'Manual' } | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue",
                    "  try { Set-NetIPInterface -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -Dhcp Enabled -AutomaticMetric Enabled -ErrorAction Stop } catch { $errs += $_.Exception.Message }",
                ])
            else:
                manual_ips = [x for x in orig_ips if x.get("IPAddress")]
                ps_lines.append(
                    "  Get-NetIPAddress -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue"
                )
                for idx_ip, ip_rec in enumerate(manual_ips):
                    ip_val = _ps_quote(ip_rec["IPAddress"])
                    plen = int(ip_rec.get("PrefixLength") or 24)
                    gw_arg = f" -DefaultGateway {_ps_quote(orig_gws[0])}" if (idx_ip == 0 and orig_gws) else ""
                    ps_lines.append(
                        f"  try {{ New-NetIPAddress -InterfaceIndex $ad.ifIndex -IPAddress {ip_val} -PrefixLength {plen}{gw_arg} -Confirm:$false -ErrorAction Stop | Out-Null }} catch {{ $errs += $_.Exception.Message }}"
                    )
            if dns_to_set:
                dns_arr = ",".join(_ps_quote(d) for d in dns_to_set)
                ps_lines.append(
                    f"  try {{ Set-DnsClientServerAddress -InterfaceIndex $ad.ifIndex -ServerAddresses @({dns_arr}) -ErrorAction Stop }} catch {{ $errs += $_.Exception.Message }}"
                )
            else:
                ps_lines.append(
                    "  try { Set-DnsClientServerAddress -InterfaceIndex $ad.ifIndex -ResetServerAddresses -ErrorAction Stop } catch { $errs += $_.Exception.Message }"
                )
            reg_dns_ps = "$true" if reg_dns else "$false"
            ps_lines.append(
                f"  try {{ Set-DnsClient -InterfaceIndex $ad.ifIndex -RegisterThisConnectionsAddress {reg_dns_ps} -ErrorAction Stop }} catch {{ $errs += $_.Exception.Message }}"
            )
            if v6_enabled is False:
                ps_lines.append(
                    "  try { Disable-NetAdapterBinding -Name $ad.Name -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction Stop } catch { $errs += $_.Exception.Message }"
                )
            else:
                ps_lines.append(
                    "  try { Enable-NetAdapterBinding -Name $ad.Name -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction Stop } catch { $errs += $_.Exception.Message }"
                )
            ps_lines.append("  @{ found = $true; errors = $errs } | ConvertTo-Json -Compress")
            ps_lines.append("}")
            raw_res = _ps("\n".join(ps_lines))
            ps_meta = json.loads(raw_res) if raw_res and raw_res.strip().startswith("{") else {"found": True, "errors": []}
            if not ps_meta.get("found", True):
                results.append({"iface": name, "status": "adapter_not_found"})
            elif ps_meta.get("errors"):
                err_list = ps_meta["errors"] if isinstance(ps_meta["errors"], list) else [ps_meta["errors"]]
                raise RuntimeError(f"Failed restoring Windows network adapter {name!r}: {err_list}")
            else:
                results.append({"iface": name, "status": "restored_dhcp" if was_dhcp else "restored_static"})
    restored_count = sum(
        1 for r in results if str(r.get("status", "")).startswith("restored_") or r.get("status") == "flushed_ip"
    )
    skipped_count = len(results) - restored_count
    return {
        "snapshot_path": str(snapshot_path),
        "restored_count": restored_count,
        "skipped_count": skipped_count,
        "all_restored": restored_count > 0 and skipped_count == 0,
        "results": results,
    }


def isolate_usb_rndis_adapter(
    static_ip: str = "192.168.77.12",
    *,
    mode: str = "management",
    target_iface: str | None = None,
    usb_topology: dict[str, Any] | None = None,
    include_zte_android: bool = False,
    snapshot_path: Path | None = None,
    allow_host_route_hijack: bool = False,
) -> dict[str, Any]:
    """Configure ONLY the correlated F50 Pro USB interface (`management` LAN-only; Windows blocks `internet-exit` by default)."""
    if mode not in ("management", "internet-exit"):
        raise ValueError(f"Unsupported host network mode {mode!r}; expected 'management' or 'internet-exit'")

    plat = detect_host_platform()
    if mode == "internet-exit":
        if plat == "win64" and not allow_host_route_hijack:
            raise RuntimeError(
                "Refusing internet-exit on Windows without explicit allow_host_route_hijack=True "
                "(management isolation prevents host route hijack)."
            )
        restored: list[dict[str, Any]] = []
        if snapshot_path is not None and snapshot_path.is_file():
            rest = restore_network_snapshot(
                snapshot_path,
                force=False,
                target_names={target_iface} if target_iface else None,
            )
            restored = rest.get("results", [])
        elif plat == "win64":
            try:
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
                if not sel["ambiguous"]:
                    for t in sel["targets"]:
                        snap = _snapshot_windows_adapter(t["name"])
                        live_ips = [x.get("IPAddress") for x in snap.get("ips", [])]
                        if static_ip in live_ips:
                            q_name = _ps_quote(t["name"])
                            _ps(
                                f"$ad = Get-NetAdapter -Name {q_name} -ErrorAction SilentlyContinue; "
                                "if ($ad) { "
                                "$reg = \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$($ad.InterfaceGuid)\"; "
                                "if (Test-Path $reg) { Set-ItemProperty -Path $reg -Name EnableDHCP -Value 1 -Type DWord -ErrorAction SilentlyContinue; "
                                "Remove-ItemProperty -Path $reg -Name IPAddress,SubnetMask,DefaultGateway,NameServer -ErrorAction SilentlyContinue }; "
                                "Get-NetIPAddress -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.PrefixOrigin -eq 'Manual' } | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; "
                                "Set-NetIPInterface -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -Dhcp Enabled -AutomaticMetric Enabled -ErrorAction SilentlyContinue; "
                                "Set-DnsClientServerAddress -InterfaceIndex $ad.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue; "
                                "Set-DnsClient -InterfaceIndex $ad.ifIndex -RegisterThisConnectionsAddress $true -ErrorAction SilentlyContinue; "
                                "Enable-NetAdapterBinding -Name $ad.Name -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue }"
                            )
                            restored.append({"iface": t["name"], "status": "restored_dhcp_internet_exit"})
            except Exception:
                pass
        elif plat in ("linux-x64", "linux-arm64"):
            try:
                cands = _detect_linux_net_candidates()
                sel = select_target_usb_adapters(
                    cands,
                    target_iface=target_iface,
                    usb_topology=usb_topology,
                    include_zte_android=include_zte_android,
                )
                nmcli = shutil.which("nmcli")
                if not sel["ambiguous"] and nmcli:
                    for t in sel["targets"]:
                        snap = _snapshot_linux_iface(t["name"])
                        cur_ips = [ai.get("local") for blk in snap.get("ip_addr_json", []) for ai in blk.get("addr_info", [])]
                        conn = snap.get("nm_connection", "")
                        if static_ip in cur_ips and conn and conn != "--":
                            _run_priv_posix(
                                [
                                    nmcli,
                                    "con",
                                    "mod",
                                    conn,
                                    "ipv4.method",
                                    "auto",
                                    "ipv4.addresses",
                                    "",
                                    "ipv4.gateway",
                                    "",
                                    "ipv4.never-default",
                                    "no",
                                    "ipv4.ignore-auto-dns",
                                    "no",
                                    "ipv6.method",
                                    "auto",
                                ]
                            )
                            _run_priv_posix([nmcli, "dev", "reapply", t["name"]], check=False)
                            restored.append({"iface": t["name"], "status": "restored_dhcp_internet_exit"})
            except Exception:
                pass
        elif plat == "macos":
            try:
                cands = _detect_macos_candidates()
                sel = select_target_usb_adapters(
                    cands,
                    target_iface=target_iface,
                    usb_topology=usb_topology,
                    include_zte_android=include_zte_android,
                )
                if not sel["ambiguous"]:
                    for t in sel["targets"]:
                        svc = t["network_service"]
                        snap = _snapshot_macos_service(svc, t["device"])
                        if f"IP address: {static_ip}" in snap.get("getinfo", ""):
                            _run_priv_posix(["networksetup", "-setdhcp", svc])
                            _run_priv_posix(["networksetup", "-setdnsservers", svc, "Empty"], check=False)
                            _run_priv_posix(["networksetup", "-setv6automatic", svc], check=False)
                            restored.append({"network_service": svc, "status": "restored_dhcp_internet_exit"})
            except Exception:
                pass
        return {
            "host_platform": plat,
            "mode": "internet-exit",
            "isolated": [],
            "restored": restored,
            "note": "Internet-exit mode active; target F50 Pro DHCP/default gateway enabled.",
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
        _save_initial_snapshot(snapshot_path, static_ip, snapshots)

        target_names = [t["name"] for t in targets]
        names_ps = ",".join(_ps_quote(n) for n in target_names)
        q_ip = _ps_quote(static_ip)
        ps_script = f"""
$ErrorActionPreference = 'Stop'
$ads = @(Get-NetAdapter -ErrorAction Stop | Where-Object {{ $_.Name -in @({names_ps}) }})
$updated = @()
$applyErrs = @()
foreach ($ad in $ads) {{
    $reg = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$($ad.InterfaceGuid)"
    if (Test-Path $reg) {{
        try {{
            Set-ItemProperty -Path $reg -Name EnableDHCP -Value 0 -Type DWord -ErrorAction Stop
            Set-ItemProperty -Path $reg -Name IPAddress -Value ([string[]]@({q_ip})) -Type MultiString -ErrorAction Stop
            Set-ItemProperty -Path $reg -Name SubnetMask -Value ([string[]]@('255.255.255.0')) -Type MultiString -ErrorAction Stop
            Set-ItemProperty -Path $reg -Name DefaultGateway -Value ([string[]]@()) -Type MultiString -ErrorAction Stop
            Set-ItemProperty -Path $reg -Name NameServer -Value '' -Type String -ErrorAction Stop
            Remove-ItemProperty -Path $reg -Name DhcpDefaultGateway -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $reg -Name DhcpNameServer -ErrorAction SilentlyContinue
        }} catch {{ $applyErrs += ('reg:' + $_.Exception.Message) }}
    }}
    try {{ Disable-NetAdapterBinding -Name $ad.Name -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction Stop }} catch {{ $applyErrs += ('v6:' + $_.Exception.Message) }}
    try {{ Set-NetIPInterface -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -Dhcp Disabled -AutomaticMetric Disabled -InterfaceMetric 5000 -ErrorAction Stop }} catch {{ $applyErrs += ('ipif:' + $_.Exception.Message) }}
    Get-NetIPAddress -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {{ $_.IPAddress -ne {q_ip} }} | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    if (-not (Get-NetIPAddress -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {{ $_.IPAddress -eq {q_ip} }})) {{
        try {{ New-NetIPAddress -InterfaceIndex $ad.ifIndex -IPAddress {q_ip} -PrefixLength 24 -Confirm:$false -ErrorAction Stop | Out-Null }} catch {{ $applyErrs += ('newip:' + $_.Exception.Message) }}
    }}
    try {{ Set-DnsClientServerAddress -InterfaceIndex $ad.ifIndex -ResetServerAddresses -ErrorAction Stop }} catch {{ $applyErrs += ('dns:' + $_.Exception.Message) }}
    try {{ Set-DnsClient -InterfaceIndex $ad.ifIndex -RegisterThisConnectionsAddress $false -ErrorAction Stop }} catch {{ $applyErrs += ('regdns:' + $_.Exception.Message) }}
    Get-NetRoute -InterfaceIndex $ad.ifIndex -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    $updated += @{{ name = $ad.Name; ifIndex = $ad.ifIndex; pnp_id = $ad.PnpDeviceID; ip = {q_ip} }}
}}
Start-Sleep -Seconds 2
$targetIdx = @($ads | ForEach-Object {{ $_.ifIndex }})
$qErrs = @($applyErrs)
$readback = @()
foreach ($ad in $ads) {{
    $ifv4 = $null; $ips = @(); $dns = @(); $v6 = $true; $regDns = $true; $qOk = $true
    try {{ $ifv4 = Get-NetIPInterface -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction Stop }} catch {{ $qOk = $false; $qErrs += ('readback_ifv4:' + $_.Exception.Message) }}
    try {{ $ips = @(Get-NetIPAddress -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction Stop | Select-Object IPAddress,PrefixLength) }} catch {{ $qOk = $false; $qErrs += ('readback_ips:' + $_.Exception.Message) }}
    try {{ $dnsObj = Get-DnsClientServerAddress -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction Stop; $dns = @($dnsObj.ServerAddresses | Where-Object {{ $_ }}) }} catch {{ $qOk = $false; $qErrs += ('readback_dns:' + $_.Exception.Message) }}
    try {{ $v6Obj = Get-NetAdapterBinding -Name $ad.Name -ComponentID ms_tcpip6 -ErrorAction Stop; $v6 = [bool]$v6Obj.Enabled }} catch {{ $qOk = $false; $qErrs += ('readback_v6:' + $_.Exception.Message) }}
    try {{ $regObj = Get-DnsClient -InterfaceIndex $ad.ifIndex -ErrorAction Stop; $regDns = [bool]$regObj.RegisterThisConnectionsAddress }} catch {{ $qOk = $false; $qErrs += ('readback_regdns:' + $_.Exception.Message) }}
    $hasIp = (@($ips | Where-Object {{ $_.IPAddress -eq {q_ip} -and $_.PrefixLength -eq 24 }}).Count -ge 1)
    if (-not $hasIp) {{ $qErrs += ('readback_ip_missing:' + $ad.Name) }}
    if (-not $ifv4 -or ($ifv4.Dhcp -ne 'Disabled')) {{ $qErrs += ('readback_dhcp_not_disabled:' + $ad.Name) }}
    if (-not $ifv4 -or ([int]$ifv4.InterfaceMetric -ne 5000)) {{ $qErrs += ('readback_metric_mismatch:' + $ad.Name) }}
    if ($v6 -eq $true) {{ $qErrs += ('readback_ipv6_still_enabled:' + $ad.Name) }}
    if ($dns.Count -gt 0) {{ $qErrs += ('readback_dns_not_empty:' + $ad.Name) }}
    if ($regDns -eq $true) {{ $qErrs += ('readback_register_dns_enabled:' + $ad.Name) }}
    $readback += @{{ name = $ad.Name; pnp_id = $ad.PnpDeviceID; query_ok = $qOk; ip_ok = $hasIp; dhcp = if($ifv4){{[string]$ifv4.Dhcp}}else{{'unknown'}}; metric = if($ifv4){{[int]$ifv4.InterfaceMetric}}else{{-1}}; ipv6_enabled = [bool]$v6; dns_count = $dns.Count; register_dns = [bool]$regDns }}
}}
$allRoutes = @()
try {{ $allRoutes = @(Get-NetRoute -ErrorAction Stop | Select-Object DestinationPrefix,ifIndex,InterfaceAlias,NextHop,RouteMetric) }} catch {{ if ($_.CategoryInfo.Category -ne 'ObjectNotFound') {{ $qErrs += ('routes:' + $_.Exception.Message) }} }}
$routes = @($allRoutes | Where-Object {{ ($_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0') -and ($_.ifIndex -in $targetIdx) }} | Select-Object ifIndex,InterfaceAlias,NextHop,RouteMetric)
@{{ isolated = $updated; readback = $readback; target_default_routes = $routes; query_errors = $qErrs }} | ConvertTo-Json -Depth 4 -Compress
"""
        raw = _ps(ps_script)
        data = json.loads(raw) if raw else {"isolated": [], "target_default_routes": [], "query_errors": ["empty_ps_output"]}
        if data.get("target_default_routes"):
            raise RuntimeError(f"Default gateway leak persists on correlated F50 Pro adapter: {data['target_default_routes']}")
        if data.get("query_errors"):
            raise RuntimeError(f"Windows route verification failed after isolation: {data['query_errors']}")
        audit = audit_default_routes(
            target_iface=target_iface,
            usb_topology=usb_topology,
            include_zte_android=include_zte_android,
        )
        if audit.get("usb_default_route_leak") or audit.get("audit_incomplete"):
            raise RuntimeError(f"Windows default gateway leak or incomplete route audit after isolation: {audit}")
        data["audit"] = audit
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
        _save_initial_snapshot(snapshot_path, static_ip, snapshots)

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
        if audit.get("usb_default_route_leak") or audit.get("audit_incomplete"):
            raise RuntimeError(f"Linux default gateway leak or incomplete route audit after isolation: {audit}")
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
        _save_initial_snapshot(snapshot_path, static_ip, snapshots)

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
        if audit.get("usb_default_route_leak") or audit.get("audit_incomplete"):
            raise RuntimeError(f"macOS default gateway leak or incomplete route audit after isolation: {audit}")
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
        pnp_regex = "VID_1D6B&PID_0104|VID_19D2" if include_zte_android else "VID_1D6B&PID_0104"
        raw = _ps(
            "$qErrs = @();"
            "$allRoutes = @(); try { $allRoutes = @(Get-NetRoute -ErrorAction Stop | Select-Object DestinationPrefix,ifIndex,InterfaceAlias,NextHop,RouteMetric) } catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { $qErrs += ('routes:' + $_.Exception.Message) } };"
            "$r4 = @($allRoutes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } | Select-Object ifIndex,InterfaceAlias,NextHop,RouteMetric);"
            "$r6 = @($allRoutes | Where-Object { $_.DestinationPrefix -eq '::/0' } | Select-Object ifIndex,InterfaceAlias,NextHop,RouteMetric);"
            f"$usb = @(); try {{ $usb = @(Get-NetAdapter -ErrorAction Stop | Where-Object {{ $_.PnpDeviceID -match '{pnp_regex}' }} | Select-Object ifIndex,Name,InterfaceDescription,PnpDeviceID,Status) }} catch {{ if ($_.CategoryInfo.Category -ne 'ObjectNotFound') {{ $qErrs += ('usb:' + $_.Exception.Message) }} }};"
            "@{ ipv4_default = $r4; ipv6_default = $r6; rndis_adapters = $usb; query_errors = $qErrs } | ConvertTo-Json -Depth 4 -Compress"
        )
        info = json.loads(raw)
        all_cands = info.get("rndis_adapters", [])
        cands = [a for a in all_cands if a.get("Name") == target_iface] if target_iface else list(all_cands)
        if target_iface and not cands and all_cands:
            # Stale/renamed --target-iface must NEVER mask an active default-route leak on a live F50 Pro adapter.
            cands = list(all_cands)
            info["target_iface_not_found"] = target_iface
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
        q_errs = info.get("query_errors")
        if q_errs:
            info["audit_incomplete"] = True
            info["warning"] = f"Windows route/adapter query failed: {q_errs}"
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
        stale_target_iface: str | None = None
        if target_iface and not target_names:
            fallback_sel = select_target_usb_adapters(
                cands,
                usb_topology=usb_topology,
                include_zte_android=include_zte_android,
            )
            if fallback_sel["targets"]:
                target_names = {x["name"] for x in fallback_sel["targets"]}
                stale_target_iface = target_iface
        if not shutil.which("ip"):
            out_miss: dict[str, Any] = {
                "host_platform": plat,
                "usb_default_route_leak": False,
                "audit_incomplete": True,
                "usb_adapters": sel["targets"],
                "ambiguous": sel["ambiguous"],
                "warning": "ip command missing",
            }
            if stale_target_iface:
                out_miss["target_iface_not_found"] = stale_target_iface
            return out_miss
        r4 = _run_cmd(["ip", "-j", "route", "show", "default"], check=False)
        r6 = _run_cmd(["ip", "-j", "-6", "route", "show", "default"], check=False)
        # Always parse whichever address family succeeded so an active IPv4 leak is never masked by an IPv6 query error.
        info = parse_linux_ip_routes(
            r4.stdout if r4.returncode == 0 else "[]",
            r6.stdout if r6.returncode == 0 else "[]",
            target_names,
        )
        info["host_platform"] = plat
        info["usb_adapters"] = sel["targets"]
        info["ambiguous"] = sel["ambiguous"]
        info["ignored_non_target_ifaces"] = sel["ignored"]
        if stale_target_iface:
            info["target_iface_not_found"] = stale_target_iface
        if r4.returncode != 0 or r6.returncode != 0:
            info["audit_incomplete"] = True
            info["warning"] = f"ip route inspection failed (rc4={r4.returncode}, rc6={r6.returncode})"
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
        stale_mac_iface: str | None = None
        if target_iface and not target_devs:
            fallback_mac = select_target_usb_adapters(
                cands,
                usb_topology=usb_topology,
                include_zte_android=include_zte_android,
            )
            fb_devs = {x["device"] for x in fallback_mac["targets"] if x.get("device")}
            if fb_devs:
                target_devs = fb_devs
                stale_mac_iface = target_iface
        r4 = _run_cmd(["netstat", "-rn", "-f", "inet"], check=False)
        r6 = _run_cmd(["netstat", "-rn", "-f", "inet6"], check=False)
        info = parse_macos_netstat_routes(
            r4.stdout if r4.returncode == 0 else "",
            r6.stdout if r6.returncode == 0 else "",
            target_devs,
        )
        info["usb_adapters"] = sel["targets"]
        info["ambiguous"] = sel["ambiguous"]
        info["ignored_non_target_services"] = sel["ignored"]
        if stale_mac_iface:
            info["target_iface_not_found"] = stale_mac_iface
        if r4.returncode != 0 or r6.returncode != 0:
            info["audit_incomplete"] = True
            info["warning"] = f"netstat route inspection failed (rc4={r4.returncode}, rc6={r6.returncode})"
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
    p_aud.add_argument("--include-zte-android", action="store_true", help="Also inspect stock ZTE Android 19D2:024* adapters")
    sub.add_parser("bind-rndis", help="Bind Windows RNDIS6 driver (no-op on POSIX)")
    p_iso = sub.add_parser("isolate", help="Isolate correlated F50 Pro USB adapter to static management IP only")
    p_iso.add_argument("--ip", default="192.168.77.12")
    p_iso.add_argument("--mode", default="management", choices=["management", "internet-exit"])
    p_iso.add_argument("--allow-host-route-hijack", action="store_true", help="Explicit override required to use internet-exit on Windows")
    p_iso.add_argument("--target-iface")
    p_iso.add_argument("--snapshot", type=Path)
    p_res = sub.add_parser("restore", help="Restore saved network snapshot after unplugging F50 Pro USB")
    p_res.add_argument("--snapshot", type=Path, required=True)
    p_res.add_argument("--force", action="store_true")
    args = parser.parse_args()

    if args.cmd == "audit":
        res = audit_default_routes(target_iface=args.target_iface, include_zte_android=args.include_zte_android)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 1 if (res.get("usb_default_route_leak") or res.get("audit_incomplete")) else 0
    if args.cmd == "bind-rndis":
        clear_negative_usbflags_rndis()
        res = bind_inbox_rndis_driver(install=True)
        time.sleep(2)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0
    if args.cmd == "restore":
        res = restore_network_snapshot(args.snapshot, force=args.force)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0 if res.get("all_restored") else 1
    if args.mode == "internet-exit" and detect_host_platform() == "win64" and not args.allow_host_route_hijack:
        raise RuntimeError(
            "Refusing --mode internet-exit on Windows without --allow-host-route-hijack "
            "(management isolation protects host Wi-Fi/Ethernet from route hijack; connect via F50 Pro Wi-Fi instead)."
        )
    res = isolate_usb_rndis_adapter(
        static_ip=args.ip,
        mode=args.mode,
        target_iface=args.target_iface,
        snapshot_path=args.snapshot,
        allow_host_route_hijack=bool(args.allow_host_route_hijack),
    )
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
