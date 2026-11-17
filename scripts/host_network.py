"""Cross-platform host USB RNDIS/NCM driver binding and strict gateway isolation helpers."""
from __future__ import annotations

import argparse
import ctypes as c
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from common import detect_host_platform, win_no_window_kwargs


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
    """Run a privileged system network configuration command directly as root or via non-interactive sudo."""
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


def clear_negative_usbflags_rndis() -> bool:
    """Clear negative cached OS descriptor flag on 1D6B:0104 Linux RNDIS gadget if present (Windows only)."""
    if sys.platform != "win32":
        return False
    out = _ps(
        "$k='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\UsbFlags\\1D6B01040612';"
        "if (Test-Path $k) { Remove-Item $k -Recurse -Force -ErrorAction SilentlyContinue; 'REMOVED' } else { 'CLEAN' }"
    )
    return "REMOVED" in out


def bind_inbox_rndis_driver(*, install: bool = True) -> dict[str, Any]:
    """Bind Microsoft inbox netrndis.inf RNDIS6 driver on Windows; native kernel drivers on POSIX."""
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
    if len(ids) != 1:
        raise ValueError(f"Expected 1 unbound F50 Pro RNDIS device, found {len(ids)}: {ids}")

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


def _detect_linux_usb_ifaces() -> list[dict[str, str]]:
    """Detect Linux USB NCM/RNDIS network interfaces matching F50 Pro / OpenWrt 1D6B:0104 or 192.168.77.x."""
    ifaces: list[dict[str, str]] = []
    seen: set[str] = set()
    net_root = Path("/sys/class/net")
    if net_root.is_dir():
        for entry in sorted(net_root.iterdir()):
            name = entry.name
            if name == "lo":
                continue
            uevent = entry / "device" / "uevent"
            modalias = entry / "device" / "modalias"
            driver_text = ""
            for probe in (uevent, modalias):
                if probe.is_file():
                    try:
                        driver_text += probe.read_text(encoding="utf-8", errors="ignore") + "\n"
                    except OSError:
                        pass
            if re.search(r"cdc_ncm|rndis_host|cdc_ether|v1D6Bp0104|v19D2|usb", driver_text, re.I) or name.startswith("usb"):
                ifaces.append({"name": name, "driver": driver_text.strip().splitlines()[0] if driver_text.strip() else "usb"})
                seen.add(name)

    if shutil.which("ip"):
        res = _run_cmd(["ip", "-j", "addr", "show"], check=False)
        if res.returncode == 0 and res.stdout.strip():
            try:
                for item in json.loads(res.stdout):
                    ifname = item.get("ifname", "")
                    if not ifname or ifname in seen:
                        continue
                    for ai in item.get("addr_info", []):
                        local = str(ai.get("local", ""))
                        if local.startswith("192.168.77."):
                            ifaces.append({"name": ifname, "driver": f"ip:{local}"})
                            seen.add(ifname)
                            break
            except json.JSONDecodeError:
                pass
    return ifaces


def parse_linux_ip_routes(v4_json: str, v6_json: str, usb_iface_names: set[str]) -> dict[str, Any]:
    """Parse Linux `ip -j route show default` JSON outputs and flag any USB gateway leak."""
    v4 = json.loads(v4_json) if v4_json.strip() else []
    v6 = json.loads(v6_json) if v6_json.strip() else []
    leaks = [
        r
        for r in v4 + v6
        if r.get("dev") in usb_iface_names or str(r.get("gateway", "")).startswith(("192.168.77.", "192.168.0."))
    ]
    return {
        "host_platform": "linux",
        "ipv4_default": v4,
        "ipv6_default": v6,
        "usb_default_route_leak": bool(leaks),
        "leaks": leaks,
    }


def parse_macos_hardware_ports(ports_output: str) -> list[dict[str, str]]:
    """Parse `networksetup -listallhardwareports` into {port, device, mac} dicts."""
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
            cur["port"] = line.split(":", 1)[1].strip()
        elif line.startswith("Device:"):
            cur["device"] = line.split(":", 1)[1].strip()
        elif line.startswith("Ethernet Address:"):
            cur["mac"] = line.split(":", 1)[1].strip()
    if cur:
        ports.append(cur)
    return ports


def _parse_macos_default_lines(netstat_output: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for raw in netstat_output.splitlines():
        parts = raw.split()
        if len(parts) >= 4 and parts[0] == "default":
            out.append({"destination": parts[0], "gateway": parts[1], "flags": parts[2], "netif": parts[-1]})
    return out


def parse_macos_netstat_routes(v4_text: str, v6_text: str, usb_devs: set[str]) -> dict[str, Any]:
    """Parse macOS `netstat -rn` tables and flag default gateway routes via USB NCM/RNDIS."""
    r4 = _parse_macos_default_lines(v4_text)
    r6 = _parse_macos_default_lines(v6_text)
    leaks = [
        r
        for r in r4 + r6
        if r.get("netif") in usb_devs or str(r.get("gateway", "")).startswith(("192.168.77.", "192.168.0."))
    ]
    return {
        "host_platform": "macos",
        "ipv4_default": r4,
        "ipv6_default": r6,
        "usb_default_route_leak": bool(leaks),
        "leaks": leaks,
    }


def _detect_macos_usb_ports() -> list[dict[str, str]]:
    res = _run_cmd(["networksetup", "-listallhardwareports"], check=False)
    ports = parse_macos_hardware_ports(res.stdout) if res.returncode == 0 else []
    usb: list[dict[str, str]] = []
    for item in ports:
        pname = item.get("port", "")
        dev = item.get("device", "")
        if not dev:
            continue
        is_usb_name = bool(re.search(r"CDC NCM|RNDIS|Ethernet Gadget|USB.*LAN|USB Ethernet", pname, re.I))
        has_f50_ip = False
        if not is_usb_name and shutil.which("ifconfig"):
            ifcfg = _run_cmd(["ifconfig", dev], check=False)
            has_f50_ip = "192.168.77." in ifcfg.stdout
        if is_usb_name or has_f50_ip:
            usb.append(item)
    return usb


def isolate_usb_rndis_adapter(static_ip: str = "192.168.77.12") -> dict[str, Any]:
    """Configure USB RNDIS/CDC-NCM adapter(s) as static LAN-only without default gateway or DNS."""
    plat = detect_host_platform()
    if plat == "win64":
        ps_script = f"""
$ErrorActionPreference = 'Stop'
$ads = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {{ ($_.InterfaceDescription -match 'RNDIS|UsbNcm|USB Ethernet' -or $_.PnpDeviceID -match 'VID_1D6B&PID_0104') -and $_.Status -eq 'Up' }}
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
    $updated += @{{ name = $ad.Name; ifIndex = $ad.ifIndex; desc = $ad.InterfaceDescription; ip = '{static_ip}' }}
}}
Start-Sleep -Seconds 2
$routes = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object ifIndex,InterfaceAlias,NextHop,RouteMetric
@{{ isolated = $updated; default_routes = @($routes) }} | ConvertTo-Json -Depth 4 -Compress
"""
        raw = _ps(ps_script)
        data = json.loads(raw) if raw else {"isolated": [], "default_routes": []}
        for r in data.get("default_routes", []):
            if str(r.get("NextHop", "")).startswith(("192.168.77.", "192.168.0.")):
                raise RuntimeError(f"Default gateway leak detected on USB adapter: {r}")
        return data

    if plat in ("linux-x64", "linux-arm64"):
        usb_ifaces = _detect_linux_usb_ifaces()
        updated: list[dict[str, Any]] = []
        nmcli = shutil.which("nmcli")
        for item in usb_ifaces:
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

        audit = audit_default_routes()
        if audit.get("usb_default_route_leak"):
            raise RuntimeError(f"Linux default gateway leak persists after isolation: {audit['leaks']}")
        return {"host_platform": plat, "isolated": updated, "audit": audit}

    if plat == "macos":
        usb_ports = _detect_macos_usb_ports()
        updated = []
        for item in usb_ports:
            svc = item["port"]
            dev = item["device"]
            _run_priv_posix(["networksetup", "-setmanual", svc, static_ip, "255.255.255.0", ""])
            _run_priv_posix(["networksetup", "-setdnsservers", svc, "Empty"])
            _run_priv_posix(["networksetup", "-setv6off", svc], check=False)
            _run_priv_posix(["route", "-n", "delete", "default", "-ifscope", dev], check=False)
            updated.append({"service": svc, "device": dev, "ip": static_ip})
        audit = audit_default_routes()
        if audit.get("usb_default_route_leak"):
            raise RuntimeError(f"macOS default gateway leak persists after isolation: {audit['leaks']}")
        return {"host_platform": "macos", "isolated": updated, "audit": audit}

    return {
        "host_platform": plat,
        "skipped": "android-host",
        "note": "Android handles USB Ethernet tethering/routes at ConnectivityService level; disable mobile/Wi-Fi clash or enable Airplane+Wi-Fi when provisioning OpenWrt over SSH.",
    }


def audit_default_routes() -> dict[str, Any]:
    """Read-only verification that 0.0.0.0/0 and ::/0 do not route via USB RNDIS/NCM adapters."""
    if sys.platform == "win32":
        raw = _ps(
            "$r4 = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object ifIndex,InterfaceAlias,NextHop,RouteMetric);"
            "$r6 = @(Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Select-Object ifIndex,InterfaceAlias,NextHop,RouteMetric);"
            "$usb = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match 'RNDIS|UsbNcm|USB Ethernet' -or $_.PnpDeviceID -match 'VID_1D6B&PID_0104' } | Select-Object ifIndex,Name,InterfaceDescription,Status);"
            "@{ ipv4_default = $r4; ipv6_default = $r6; rndis_adapters = $usb } | ConvertTo-Json -Depth 4 -Compress"
        )
        info = json.loads(raw)
        usb_indices = {a["ifIndex"] for a in info.get("rndis_adapters", [])}
        leaks = [
            r
            for r in info.get("ipv4_default", []) + info.get("ipv6_default", [])
            if r.get("ifIndex") in usb_indices or str(r.get("NextHop", "")).startswith(("192.168.77.", "192.168.0."))
        ]
        info["host_platform"] = "win64"
        info["usb_default_route_leak"] = bool(leaks)
        info["leaks"] = leaks
        return info

    plat = detect_host_platform()
    if plat in ("linux-x64", "linux-arm64"):
        usb_ifaces = _detect_linux_usb_ifaces()
        if not shutil.which("ip"):
            return {"host_platform": plat, "usb_default_route_leak": False, "usb_adapters": usb_ifaces, "warning": "ip command missing"}
        r4 = _run_cmd(["ip", "-j", "route", "show", "default"], check=False)
        r6 = _run_cmd(["ip", "-j", "-6", "route", "show", "default"], check=False)
        info = parse_linux_ip_routes(r4.stdout if r4.returncode == 0 else "[]", r6.stdout if r6.returncode == 0 else "[]", {x["name"] for x in usb_ifaces})
        info["host_platform"] = plat
        info["usb_adapters"] = usb_ifaces
        return info

    if plat == "macos":
        usb_ports = _detect_macos_usb_ports()
        r4 = _run_cmd(["netstat", "-rn", "-f", "inet"], check=False)
        r6 = _run_cmd(["netstat", "-rn", "-f", "inet6"], check=False)
        info = parse_macos_netstat_routes(r4.stdout, r6.stdout, {x["device"] for x in usb_ports})
        info["usb_adapters"] = usb_ports
        return info

    # Android host (Termux / rooted phone)
    routes_txt = ""
    if shutil.which("ip"):
        res = _run_cmd(["ip", "route", "show", "default"], check=False)
        if res.returncode == 0:
            routes_txt = res.stdout.strip()
    leak = any(tok in routes_txt for tok in ("192.168.77.", "192.168.0."))
    return {
        "host_platform": plat,
        "rooted": bool(hasattr(os, "geteuid") and os.geteuid() == 0),
        "default_routes_text": routes_txt,
        "usb_default_route_leak": leak,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("audit", help="Verify host default gateway does not traverse USB RNDIS/NCM")
    sub.add_parser("bind-rndis", help="Bind Windows RNDIS6 driver (no-op on POSIX)")
    p_iso = sub.add_parser("isolate", help="Isolate up USB RNDIS/NCM adapter to static management IP only")
    p_iso.add_argument("--ip", default="192.168.77.12")
    args = parser.parse_args()

    if args.cmd == "audit":
        res = audit_default_routes()
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 1 if res.get("usb_default_route_leak") else 0
    if args.cmd == "bind-rndis":
        clear_negative_usbflags_rndis()
        res = bind_inbox_rndis_driver(install=True)
        time.sleep(2)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0
    res = isolate_usb_rndis_adapter(static_ip=args.ip)
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
