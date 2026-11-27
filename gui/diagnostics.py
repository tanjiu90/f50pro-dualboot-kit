"""Automated Windows diagnostics, USB device radar, driver checks, and error auto-repair for F50 Pro."""
from __future__ import annotations

import ctypes
import datetime
import hashlib
import http.cookiejar
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable


def _no_window_kwargs() -> dict[str, Any]:
    if sys.platform == "win32":
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)}
    return {}


def is_windows_admin() -> bool:
    """Return True if running with Administrator privileges on Windows (or root on POSIX)."""
    if sys.platform != "win32":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def check_disk_space(target_path: Path, *, min_gb: float = 15.0) -> dict[str, Any]:
    """Verify target drive has enough free space for ~7 GiB BROM backup + derived images."""
    probe = target_path
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    usage = shutil.disk_usage(probe)
    free_gb = round(usage.free / (1024**3), 2)
    return {
        "ok": free_gb >= min_gb,
        "path": str(probe),
        "free_gb": free_gb,
        "required_gb": min_gb,
    }


def _run_powershell(script: str, *, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
    wrapped = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); " + script
    return subprocess.run(
        ["powershell", "-NoProfile", "-Command", wrapped],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        **_no_window_kwargs(),
    )


def parse_pnputil_unisoc_drivers(pnputil_output: str, inf_dir: Path = Path(r"C:\Windows\INF")) -> dict[str, Any]:
    """Inspect `pnputil /enum-drivers` output + Windows INF headers to detect WinUSB vs conflicting serial drivers."""
    oem_files = sorted(set(re.findall(r"\boem\d+\.inf\b", pnputil_output, re.I)))
    has_4d00_winusb = False
    has_4d03_winusb = False
    winusb_infs: list[str] = []
    conflicting_serial_infs: list[str] = []

    for inf_name in oem_files:
        inf_path = inf_dir / inf_name
        if not inf_path.is_file():
            continue
        try:
            txt = inf_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        upper = txt.upper()
        if "VID_1782" not in upper:
            continue
        is_winusb = ("WINUSB.INF" in upper) or ("LIBWDI" in upper) or ("WINUSB.NT" in upper)
        is_serial = ("SPRDVCOM" in upper) or ("U2S DIAG" in upper) or ("USBSER" in upper) or ("MODEM" in upper and not is_winusb)
        if is_winusb:
            winusb_infs.append(inf_name)
            if "PID_4D00" in upper:
                has_4d00_winusb = True
            if "PID_4D03" in upper:
                has_4d03_winusb = True
        elif is_serial and ("PID_4D00" in upper or "PID_4D03" in upper):
            conflicting_serial_infs.append(inf_name)

    return {
        "installed": has_4d00_winusb and has_4d03_winusb,
        "has_4d00_winusb": has_4d00_winusb,
        "has_4d03_winusb": has_4d03_winusb,
        "winusb_infs": winusb_infs,
        "conflicting_serial_infs": conflicting_serial_infs,
    }


def inspect_unisoc_drivers() -> dict[str, Any]:
    """Check whether Windows Driver Store already has WinUSB drivers for 1782:4D00 and 1782:4D03."""
    if sys.platform != "win32":
        return {"installed": True, "has_4d00_winusb": True, "has_4d03_winusb": True, "winusb_infs": [], "conflicting_serial_infs": []}
    try:
        res = subprocess.run(
            ["pnputil", "/enum-drivers"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15.0,
            **_no_window_kwargs(),
        )
        return parse_pnputil_unisoc_drivers(res.stdout or "")
    except Exception as exc:
        return {
            "installed": False,
            "has_4d00_winusb": False,
            "has_4d03_winusb": False,
            "winusb_infs": [],
            "conflicting_serial_infs": [],
            "error": str(exc),
        }


def install_unisoc_winusb_drivers(
    tools_dir: Path,
    *,
    log_cb: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Run qmk_driver_installer.exe --force --all unisoc_drivers.txt and verify success."""
    qmk_dir = tools_dir / "host-tools-win64" / "qmk_driver_installer"
    installer = qmk_dir / "qmk_driver_installer.exe"
    drv_list = qmk_dir / "unisoc_drivers.txt"
    if not installer.is_file() or not drv_list.is_file():
        return {
            "ok": False,
            "error": f"未找到驱动安装器（{installer}），请先点击「一键拉取并准备工具包」。",
        }
    if not is_windows_admin():
        return {
            "ok": False,
            "error": "需要管理员权限才能安装 Windows 驱动，请右键「以管理员身份运行」本程序。",
        }
    cmd = [str(installer), "--force", "--all", str(drv_list)]
    if log_cb:
        log_cb("正在以 --force --all 离线预装展锐 WinUSB 驱动（1782:4D00 / 1782:4D03）...")
    res = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120.0,
        **_no_window_kwargs(),
    )
    combined = ((res.stdout or "") + "\n" + (res.stderr or "")).strip()
    if log_cb and combined:
        for line in combined.splitlines():
            log_cb(f"  [driver] {line}")
    post_check = inspect_unisoc_drivers()
    ok = (res.returncode == 0) and ("No matching device found" not in combined) and (
        post_check.get("installed") or "Success" in combined
    )
    return {
        "ok": ok,
        "returncode": res.returncode,
        "output": combined,
        "driver_store": post_check,
    }


def probe_zte_webui_identity(host: str = "http://192.168.0.1:8080", *, timeout: float = 1.8) -> dict[str, Any] | None:
    """Read-only probe of stock ZTE WebUI identity (bypasses system HTTP proxy)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    url = f"{host.rstrip('/')}/goform/goform_get_cmd_process?isTest=false&multi_data=1&cmd=model_name,cr_version,hardware_version,wa_inner_version"
    req = urllib.request.Request(url, headers={"Referer": f"{host.rstrip('/')}/index.html"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        if isinstance(data, dict) and (data.get("model_name") or data.get("cr_version")):
            return data
    except Exception:
        return None
    return None


def test_webui_password(password: str, host: str = "http://192.168.0.1:8080", *, timeout: float = 3.0) -> dict[str, Any]:
    """Verify stock ZTE WebUI login password read-only (NEVER triggers REBOOT_DEVICE)."""
    if not password:
        return {"ok": False, "reason": "empty", "message": "请先输入原厂管理后台密码（通常贴在机身背面或 192.168.0.1:8080 登录密码）。"}

    def sha_u(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest().upper()

    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(jar),
    )
    base = host.rstrip("/")
    try:
        req1 = urllib.request.Request(
            f"{base}/goform/goform_get_cmd_process?isTest=false&multi_data=1&cmd=loginfo,LD,model_name,cr_version",
            headers={"Referer": f"{base}/index.html"},
        )
        with opener.open(req1, timeout=timeout) as resp:
            info = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        return {
            "ok": False,
            "reason": "unreachable",
            "message": f"无法连接原厂管理后台 {base}（请确认 F50 Pro 已开机插线且在原厂安卓系统）：{exc}",
        }

    ld = info.get("LD")
    if not ld:
        return {"ok": False, "reason": "invalid_response", "message": "原厂后台返回异常（缺少 LD 挑战字段）。"}

    login_hash = sha_u(sha_u(password) + str(ld))
    body = urllib.parse.urlencode({"isTest": "false", "goformId": "LOGIN", "password": login_hash}).encode("utf-8")
    req2 = urllib.request.Request(
        f"{base}/goform/goform_set_cmd_process",
        data=body,
        headers={
            "Referer": f"{base}/index.html",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
        },
    )
    try:
        with opener.open(req2, timeout=timeout) as resp:
            res = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        return {"ok": False, "reason": "login_error", "message": f"验证登录请求失败：{exc}"}

    code = str(res.get("result"))
    if code in ("0", "4"):
        return {
            "ok": True,
            "model_name": info.get("model_name", ""),
            "cr_version": info.get("cr_version", ""),
            "message": f"原厂后台密码验证通过！（机型：{info.get('model_name', 'MU3356')}，固件：{info.get('cr_version', '')}）",
        }
    return {
        "ok": False,
        "reason": "wrong_password",
        "result": res,
        "message": f"原厂后台密码错误（result={code}）。请核对机身背面密码或先在浏览器打开 {base} 确认登录密码。",
    }


def parse_pnp_usb_devices(
    devices: list[dict[str, Any]],
    *,
    webui_info: dict[str, Any] | None = None,
    openwrt_ssh_open: bool = False,
) -> dict[str, Any]:
    """Classify live Windows PnP device list into F50 Pro state and detect driver/model anomalies."""
    brom_devs: list[dict[str, Any]] = []
    stock_devs: list[dict[str, Any]] = []
    openwrt_devs: list[dict[str, Any]] = []

    for dev in devices:
        pnp_id = str(dev.get("InstanceId") or dev.get("PNPDeviceID") or "").upper()
        if "VID_1782&PID_4D00" in pnp_id or "VID_1782&PID_4D03" in pnp_id:
            brom_devs.append(dev)
        elif "VID_19D2&PID_0246" in pnp_id or "VID_19D2&PID_024" in pnp_id:
            stock_devs.append(dev)
        elif "VID_1D6B&PID_0104" in pnp_id:
            openwrt_devs.append(dev)

    issues: list[dict[str, str]] = []

    if brom_devs:
        services = {str(d.get("Service") or "").lower() for d in brom_devs}
        err_devs = [d for d in brom_devs if int(d.get("ConfigManagerErrorCode") or 0) != 0]
        if err_devs or (services and not (services & {"winusb", "libusbk", "libusb0"})):
            issues.append(
                {
                    "code": "BROM_DRIVER_NOT_WINUSB",
                    "severity": "error",
                    "message": f"检测到设备已进入展锐刷机口 (1782:4D00)，但驱动未绑定 WinUSB（当前：{', '.join(sorted(services)) or '未安装'}），请点击「一键修复展锐驱动」。",
                }
            )
        return {
            "state": "brom",
            "label": "已连接：展锐刷机模式 (1782:4D00 / AutoD)",
            "devices": brom_devs,
            "issues": issues,
        }

    if openwrt_devs:
        ncm_err = [
            d
            for d in openwrt_devs
            if int(d.get("ConfigManagerErrorCode") or 0) != 0
            and ("MI_00" in str(d.get("InstanceId") or "").upper() or "NCM" in str(d.get("FriendlyName") or "").upper())
        ]
        if ncm_err:
            issues.append(
                {
                    "code": "OPENWRT_WIN10_NCM_ERROR",
                    "severity": "warn",
                    "message": "检测到 OpenWrt USB 网卡 (CDC-NCM) 在当前 Windows 下打黄色感叹号；刷机配网会自动通过 MI_02 串口切为 RNDIS，也可点击「一键隔离/修复 USB 网卡」。",
                }
            )
        return {
            "state": "openwrt",
            "label": f"已连接：F50 Pro OpenWrt ({'SSH 在线 192.168.77.1' if openwrt_ssh_open else '等待网络就绪'})",
            "openwrt_ssh_open": openwrt_ssh_open,
            "devices": openwrt_devs,
            "issues": issues,
        }

    if stock_devs:
        rndis_err = [
            d
            for d in stock_devs
            if int(d.get("ConfigManagerErrorCode") or 0) != 0
        ]
        if rndis_err:
            issues.append(
                {
                    "code": "STOCK_RNDIS_DRIVER_ERROR",
                    "severity": "error",
                    "message": "检测到 F50 Pro 原厂设备 (19D2:0246)，但 Windows RNDIS 网卡驱动异常（黄色感叹号），请点击「一键修复 USB 网卡」。",
                }
            )
        model = str((webui_info or {}).get("model_name") or "")
        ver = str((webui_info or {}).get("cr_version") or (webui_info or {}).get("wa_inner_version") or "")
        if model and model.upper() != "MU3356":
            issues.append(
                {
                    "code": "WRONG_DEVICE_MODEL",
                    "severity": "error",
                    "message": f"危险拦截：检测到机型为 {model}，不是中兴 F50 Pro (MU3356)！严禁跨型号刷机，否则会变砖！",
                }
            )
        elif not webui_info and not rndis_err:
            issues.append(
                {
                    "code": "WEBUI_NOT_REACHABLE_YET",
                    "severity": "warn",
                    "message": "已检测到 USB 设备 19D2:0246，但暂未连上 192.168.0.1:8080（若刚通电请等待约 20 秒，或检查代理软件/VPN 是否拦截了 192.168.0.1）。",
                }
            )
        label = f"已连接：F50 Pro 原厂安卓 ({model or 'MU3356'}{' · ' + ver if ver else ''})"
        return {
            "state": "stock_android",
            "label": label,
            "webui_info": webui_info,
            "devices": stock_devs,
            "issues": issues,
        }

    issues.append(
        {
            "code": "DEVICE_DISCONNECTED",
            "severity": "warn",
            "message": "未检测到 F50 Pro：请换一根确认能传数据的 USB-A 转 Type-C 线，直插电脑主板后置 USB 口（勿用纯充电线/扩展坞），通电等待约 20 秒。",
        }
    )
    return {
        "state": "disconnected",
        "label": "未检测到 F50 Pro 设备",
        "devices": [],
        "issues": issues,
    }


def detect_usb_device_state(*, probe_network: bool = True) -> dict[str, Any]:
    """Live Windows USB PnP + optional WebUI/SSH radar for F50 Pro."""
    devices: list[dict[str, Any]] = []
    if sys.platform == "win32":
        ps = (
            "$devs = Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | "
            "Where-Object { $_.PNPDeviceID -match 'VID_(1782|19D2|1D6B)' } | "
            "Select-Object Name, FriendlyName, PNPDeviceID, Service, Status, ConfigManagerErrorCode; "
            "if ($null -eq $devs) { '[]' } else { @($devs) | ConvertTo-Json -Compress -Depth 3 }"
        )
        try:
            res = _run_powershell(ps, timeout=8.0)
            if res.returncode == 0 and res.stdout.strip():
                parsed = json.loads(res.stdout.strip())
                devices = parsed if isinstance(parsed, list) else [parsed]
        except Exception:
            devices = []

    webui_info = None
    openwrt_ssh_open = False
    if probe_network:
        has_stock = any("VID_19D2" in str(d.get("PNPDeviceID") or "").upper() for d in devices)
        has_ow = any("VID_1D6B&PID_0104" in str(d.get("PNPDeviceID") or "").upper() for d in devices)
        if has_stock:
            webui_info = probe_zte_webui_identity()
        if has_ow:
            try:
                with socket.create_connection(("192.168.77.1", 22), timeout=0.6):
                    openwrt_ssh_open = True
            except OSError:
                openwrt_ssh_open = False

    return parse_pnp_usb_devices(devices, webui_info=webui_info, openwrt_ssh_open=openwrt_ssh_open)


def ensure_adb_pubkey(tools_dir: Path) -> dict[str, Any]:
    """Ensure ~/.android/adbkey.pub exists (auto-generates via bundled adb.exe if absent)."""
    pub = Path.home() / ".android" / "adbkey.pub"
    if pub.is_file():
        return {"ok": True, "created": False, "path": str(pub)}
    adb = tools_dir / "host-tools-win64" / "platform-tools" / "adb.exe"
    if not adb.is_file():
        found = shutil.which("adb")
        adb = Path(found) if found else adb
    if not adb.is_file():
        return {"ok": False, "error": "未找到 adb.exe，请先下载 Windows 工具包。"}
    pub.parent.mkdir(parents=True, exist_ok=True)
    res = subprocess.run(
        [str(adb), "keygen", str(pub.parent / "adbkey")],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15.0,
        **_no_window_kwargs(),
    )
    if res.returncode == 0 and pub.is_file():
        return {"ok": True, "created": True, "path": str(pub)}
    return {"ok": False, "error": f"adb keygen 失败：{res.stderr or res.stdout}"}


def try_repair_usb_network(kit_root: Path) -> dict[str, Any]:
    """Trigger Windows PnP rescan + run host_network.py bind-rndis & isolate if OpenWrt NIC present."""
    notes: list[str] = []
    if sys.platform == "win32":
        try:
            r = subprocess.run(
                ["pnputil", "/scan-devices"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20.0,
                **_no_window_kwargs(),
            )
            notes.append(f"pnputil /scan-devices rc={r.returncode}")
        except Exception as exc:
            notes.append(f"pnputil scan error: {exc}")

    # Import host_network from active kit_root to bind Windows inbox netrndis6 & isolate gateway
    scripts_dir = str(kit_root / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    try:
        import host_network  # type: ignore

        bind_res = host_network.bind_inbox_rndis_driver(install=True) if hasattr(host_network, "bind_inbox_rndis_driver") else {}
        iso_res = (
            host_network.isolate_usb_rndis_adapter(mode="management")
            if hasattr(host_network, "isolate_usb_rndis_adapter")
            else {}
        )
        return {"ok": True, "notes": notes, "bind": bind_res, "isolate": iso_res}
    except Exception as exc:
        return {"ok": False, "notes": notes, "error": str(exc)}


def diagnose_failure(log_text: str, *, failure_report: dict[str, Any] | None = None) -> dict[str, Any]:
    """Map raw failure output / flash_failure_report.json to a human-readable Chinese diagnosis and one-click fix."""
    text = log_text or ""
    low = text.lower()

    if "no matching device found" in low:
        return {
            "code": "DRIVER_MISSING_ALL_FLAG",
            "title": "展锐刷机驱动未预装（No matching device found）",
            "cause": "驱动安装器缺少 --all 参数，且设备当前未处于 1782:4D00 下载模式，因此驱动没有写入系统。",
            "steps": [
                "点击下方「一键安装/修复展锐驱动」，程序会自动使用 --force --all 预装 1782:4D00 与 1782:4D03 驱动。",
                "若弹出 Windows 驱动安装确认框，点「安装 / 是」。",
            ],
            "fix_action": "install_drivers",
            "fix_label": "一键安装/修复展锐驱动 (--force --all)",
        }

    if "webuiautherror" in low or "webui login failed" in low:
        return {
            "code": "WEBUI_BAD_PASSWORD",
            "title": "原厂管理后台密码错误",
            "cause": "填写的 WebUI 密码被 192.168.0.1:8080 拒绝登录，脚本无法自动发重启指令进入下载模式。",
            "steps": [
                "核对 F50 Pro 机身背面贴纸上的默认管理员密码，或你自己在浏览器里改过的密码。",
                "先点击密码框旁的「验证密码」按钮确认通过，再重新开始。",
            ],
            "fix_action": "focus_webui_password",
            "fix_label": "去核对并验证原厂密码",
        }

    if "stock webui unreachable" in low or "192.168.0.1:8080" in low and ("unreachable" in low or "timed out" in low or "refused" in low):
        return {
            "code": "WEBUI_UNREACHABLE",
            "title": "无法连接 F50 Pro 原厂后台 (192.168.0.1:8080)",
            "cause": "电脑未识别到 F50 Pro 的 RNDIS USB 网卡，或数据线仅支持充电，或本机 VPN/代理软件拦截了局域网地址。",
            "steps": [
                "换一根确认能给手机传数据的 USB-A 转 Type-C 线，直插台式机主板后置 USB 口。",
                "点击下方「一键修复 USB 网卡」刷新设备管理器并尝试绑定微软 RNDIS 驱动。",
                "如电脑开着 Clash TUN / 全局 VPN，请先临时关闭后再重试。",
            ],
            "fix_action": "repair_usb_network",
            "fix_label": "一键扫描并修复 USB 网卡",
        }

    if any(k in low for k in ("waiting for boot_diag", "find port failed", "libusb_error_access", "libusb_error_not_found", "timed out waiting for sprd4")):
        return {
            "code": "BROM_HANDSHAKE_FAILED",
            "title": "未能抓到展锐刷机端口 (1782:4D00 / boot_diag 超时)",
            "cause": "常见原因：① 展锐 WinUSB 驱动未装或被旧串口驱动 (SPRD U2S Diag) 抢占；② 数据线/USB 口不稳定；③ 设备没有触发重启。",
            "steps": [
                "先点下方「一键安装/修复展锐驱动」确保 1782:4D00 与 1782:4D03 已预装 WinUSB。",
                "确认能打开 http://192.168.0.1:8080 且原厂密码验证通过；换主板后置 USB 口重试。",
                "如曾装过老版展锐串口驱动，设备重启进下载口时需在设备管理器卸载 SPRD U2S Diag 或用 Zadig 替换为 WinUSB。",
            ],
            "fix_action": "install_drivers",
            "fix_label": "一键安装/修复展锐驱动",
        }

    if "target unit identity mismatch" in low or "unit_identity" in low and "mismatch" in low:
        return {
            "code": "DEVICE_IDENTITY_MISMATCH",
            "title": "安全锁拦截：备份目录与当前设备不匹配",
            "cause": "检测到当前插着的 F50 Pro 与所选工作目录里的原厂备份不是同一台机器！安全锁已主动拦截，避免刷成砖。",
            "steps": [
                "请为这台新机器切换一个新的工作目录（例如 my-f50pro-2），重新备份本机原厂分区后再刷。",
            ],
            "fix_action": "new_workdir",
            "fix_label": "一键新建独立设备工作目录",
        }

    if "missing adb rsa public key" in low or "adbkey.pub" in low:
        return {
            "code": "MISSING_ADB_KEY",
            "title": "缺少本机 ADB 公钥 (adbkey.pub)",
            "cause": "安卓 Root 方案需要把本机 ADB 公钥预置进设备，当前用户目录下尚未生成。",
            "steps": ["点击下方按钮自动调用 adb.exe 生成 RSA 密钥对即可解决。"],
            "fix_action": "generate_adb_key",
            "fix_label": "一键生成 ADB 密钥",
        }

    if failure_report or "flash_failure_report.json" in low or ("readback" in low and "mismatch" in low):
        return {
            "code": "FLASH_SAFE_STOP",
            "title": "刷写/读回校验中途安全暂停（未切槽、未盲目重启）",
            "cause": "写入或读回 SHA-256 核验时出现传输中断；工具已原地止损，你的原厂安卓 _a 槽通常完好无损！",
            "steps": [
                "切勿慌张反复插拔断电！先检查 USB 线是否松动并更换主板后置口。",
                "排查完线材后可再次点击刷入重试，或使用「救砖回退原厂安卓 (_a)」切回原系统。",
            ],
            "fix_action": "export_diag",
            "fix_label": "导出脱敏诊断报告",
        }

    if any(k in low for k in ("sha-256 mismatch", "urlerror", "http error", "getaddrinfo failed", "ssl", "connection reset", "winerror 10054", "无法连接 github")):
        return {
            "code": "GITHUB_NETWORK_ERROR",
            "title": "GitHub 资源下载失败或网络超时",
            "cause": "当前网络直连 GitHub Releases 不稳定或被中断。",
            "steps": [
                "点击下方「一键切换国内镜像并重试」，程序会自动通过镜像拉取并严格做 SHA-256 校验。",
                "或手动从浏览器下载压缩包放入 workspace\\bundle-cache 文件夹走离线校验。",
            ],
            "fix_action": "switch_mirror",
            "fix_label": "一键切换国内加速镜像",
        }

    return {
        "code": "GENERIC_FAILURE",
        "title": "执行遇到异常",
        "cause": "请查看日志末尾红色报错信息，或导出脱敏诊断报告发给群友/开发者快速定位。",
        "steps": [
            "先点击「一键体检并准备环境」确认驱动、设备连接和空间均为绿灯。",
            "点击下方「导出脱敏诊断报告」自动隐藏密码与隐私信息后保存为 txt。",
        ],
        "fix_action": "export_diag",
        "fix_label": "导出脱敏诊断报告",
    }


def sanitize_diagnostic_text(raw: str, *, secrets: list[str] | None = None) -> str:
    """Scrub passwords, IMEIs, ICCIDs, IMSIs, tokens, and local Windows usernames before exporting logs."""
    out = raw or ""
    for sec in secrets or []:
        if sec and len(sec) >= 2:
            out = out.replace(sec, "<REDACTED>")
    out = re.sub(r"(--(?:webui-password|wifi-password|root-password)\s+)(?:\"[^\"]*\"|'[^']*'|\S+)", r"\1<REDACTED>", out)
    out = re.sub(r"([A-Za-z]:[/\\]+Users[/\\]+)[^/\\\s\"']+", r"\1<USER>", out, flags=re.I)
    out = re.sub(r"(?<![0-9a-fA-F])86\d{13}(?![0-9a-fA-F])", "<IMEI_REDACTED>", out)
    out = re.sub(r"(?<![0-9a-fA-F])(?:8986\d{14,16}|460\d{12})(?![0-9a-fA-F])", "<SIM_ID_REDACTED>", out)
    out = re.sub(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{10,}\b", "<TOKEN_REDACTED>", out)
    return out


def build_sanitized_diagnostic_report(
    *,
    kit_version: str,
    workspace_dir: Path,
    log_tail: str,
    secrets: list[str] | None = None,
) -> str:
    """Collect host diagnostics and return a clean, PII-redacted text report ready for sharing."""
    driver_info = inspect_unisoc_drivers()
    usb_info = detect_usb_device_state(probe_network=True)
    disk_info = check_disk_space(workspace_dir)
    payload = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "is_admin": is_windows_admin(),
        "kit_version": kit_version,
        "disk": disk_info,
        "unisoc_drivers": driver_info,
        "usb_radar": {
            "state": usb_info.get("state"),
            "label": usb_info.get("label"),
            "issues": usb_info.get("issues"),
            "webui_model": (usb_info.get("webui_info") or {}).get("model_name"),
            "webui_version": (usb_info.get("webui_info") or {}).get("cr_version"),
        },
    }
    raw = (
        "=== F50 Pro 一键刷机工具脱敏诊断报告 ===\n"
        + json.dumps(payload, indent=2, ensure_ascii=False)
        + "\n\n=== 最近运行日志（已自动脱敏） ===\n"
        + log_tail[-8000:]
        + "\n"
    )
    return sanitize_diagnostic_text(raw, secrets=secrets)
