"""Windows USB RNDIS driver binding and strict gateway isolation helpers."""
from __future__ import annotations

import argparse
import ctypes as c
import json
import subprocess
import sys
import time
from typing import Any


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
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if res.returncode != 0:
        raise RuntimeError(f"PowerShell failed ({res.returncode}): {(res.stderr or '').strip()}")
    return (res.stdout or "").strip()


def clear_negative_usbflags_rndis() -> bool:
    """Clear negative cached OS descriptor flag on 1D6B:0104 Linux RNDIS gadget if present."""
    if sys.platform != "win32":
        return False
    out = _ps(
        "$k='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\UsbFlags\\1D6B01040612';"
        "if (Test-Path $k) { Remove-Item $k -Recurse -Force -ErrorAction SilentlyContinue; 'REMOVED' } else { 'CLEAN' }"
    )
    return "REMOVED" in out


def bind_inbox_rndis_driver(*, install: bool = True) -> dict[str, Any]:
    """Bind Microsoft inbox netrndis.inf RNDIS6 driver to present VID_1D6B&PID_0104 RNDIS child."""
    if sys.platform != "win32":
        return {"skipped": "non-windows"}
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


def isolate_usb_rndis_adapter(static_ip: str = "192.168.77.12") -> dict[str, Any]:
    """Configure Windows USB RNDIS adapter(s) as static LAN-only without default gateway or DNS."""
    if sys.platform != "win32":
        return {"skipped": "non-windows"}
    ps_script = f"""
$ErrorActionPreference = 'Stop'
$ads = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {{ $_.InterfaceDescription -match 'RNDIS' -and $_.Status -eq 'Up' }}
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


def audit_default_routes() -> dict[str, Any]:
    """Read-only verification that 0.0.0.0/0 and ::/0 do not route via USB RNDIS adapters."""
    if sys.platform != "win32":
        return {"skipped": "non-windows"}
    raw = _ps(
        "$r4 = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object ifIndex,InterfaceAlias,NextHop,RouteMetric);"
        "$r6 = @(Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Select-Object ifIndex,InterfaceAlias,NextHop,RouteMetric);"
        "$usb = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match 'RNDIS' } | Select-Object ifIndex,Name,InterfaceDescription,Status);"
        "@{ ipv4_default = $r4; ipv6_default = $r6; rndis_adapters = $usb } | ConvertTo-Json -Depth 4 -Compress"
    )
    info = json.loads(raw)
    usb_indices = {a["ifIndex"] for a in info.get("rndis_adapters", [])}
    leaks = [r for r in info.get("ipv4_default", []) + info.get("ipv6_default", []) if r["ifIndex"] in usb_indices]
    info["usb_default_route_leak"] = bool(leaks)
    info["leaks"] = leaks
    return info


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("audit", help="Verify Windows default gateway does not traverse USB RNDIS")
    sub.add_parser("bind-rndis", help="Bind Microsoft RNDIS6 driver to OpenWrt 1D6B:0104")
    p_iso = sub.add_parser("isolate", help="Isolate up RNDIS adapter to static management IP only")
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
