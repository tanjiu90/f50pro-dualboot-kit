"""Automated Windows diagnostics, USB device radar, authenticated driver checks, and strict PII-sanitized reporting."""
from __future__ import annotations

import ctypes
import datetime
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable

_SAFE_MODEL_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
_SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9._ -]{1,64}$")


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


def extract_last_json_object(text: str) -> dict[str, Any] | None:
    """Parse the final top-level JSON object from mixed stdout/logs (handles nested dicts accurately)."""
    if not text:
        return None
    decoder = json.JSONDecoder()
    pos = 0
    n = len(text)
    last_obj: dict[str, Any] | None = None
    while pos < n:
        idx = text.find("{", pos)
        if idx < 0:
            break
        try:
            obj, end = decoder.raw_decode(text, idx)
            if isinstance(obj, dict):
                last_obj = obj
            pos = end
        except json.JSONDecodeError:
            pos = idx + 1
    return last_obj


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


def check_native_tool_path_compat(path: Path) -> dict[str, Any]:
    """Verify Windows path is safe for narrow-char C tools (qmk_driver_installer / spd_dump fopen) without over-rejecting valid paths."""
    raw = str(path)
    if "\x00" in raw or any(ord(c) < 32 for c in raw):
        return {"ok": False, "path": raw, "reason": "路径包含非法控制字符，请选择正常本地路径（如 D:\\F50Pro-Flasher）。"}
    # Strip drive prefix before checking Windows forbidden path characters
    tail = raw[2:] if (len(raw) >= 2 and raw[1] == ":") else raw
    if any(ch in tail for ch in ('*', '?', '"', '<', '>', '|')):
        return {"ok": False, "path": raw, "reason": "路径包含 Windows 非法文件名字符（* ? \" < > |）。"}
    if sys.platform == "win32":
        try:
            raw.encode("mbcs", errors="strict")
        except UnicodeEncodeError:
            return {
                "ok": False,
                "path": raw,
                "reason": "路径包含当前 Windows 系统代码页无法编码的字符，原生刷机/驱动工具可能无法打开文件；请将程序和工作目录移至纯英文短路径（如 D:\\F50Pro-Flasher）。",
            }
    return {"ok": True, "path": raw}


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


def _default_windows_inf_dir() -> Path:
    return Path(os.environ.get("WINDIR") or r"C:\Windows") / "INF"


def _read_inf_text(inf_path: Path) -> str:
    """Read Windows INF text supporting UTF-16LE/BE BOM, NUL-interleaved UTF-16, UTF-8, and local ANSI."""
    data = inf_path.read_bytes()
    if data.startswith(b"\xff\xfe"):
        return data.decode("utf-16-le", errors="ignore")
    if data.startswith(b"\xfe\xff"):
        return data.decode("utf-16-be", errors="ignore")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="ignore")
    if b"\x00" in data[:256]:
        return data.decode("utf-16-le", errors="ignore")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="ignore")


def parse_pnputil_unisoc_drivers(pnputil_output: str, inf_dir: Path | None = None) -> dict[str, Any]:
    """Inspect `pnputil /enum-drivers` + Windows INF headers (UTF-8 & UTF-16) for 1782:4D00/4D03 WinUSB & serial conflicts."""
    target_inf_dir = inf_dir if inf_dir is not None else _default_windows_inf_dir()
    oem_files = sorted(set(re.findall(r"\boem\d+\.inf\b", pnputil_output, re.I)))
    has_4d00_winusb = False
    has_4d03_winusb = False
    winusb_infs: list[str] = []
    conflicting_serial_infs: list[str] = []

    for inf_name in oem_files:
        inf_path = target_inf_dir / inf_name
        if not inf_path.is_file():
            continue
        try:
            txt = _read_inf_text(inf_path)
        except OSError:
            continue
        upper = txt.upper()
        if "VID_1782" not in upper:
            continue
        is_winusb = ("WINUSB.INF" in upper) or ("LIBWDI" in upper) or ("WINUSB.NT" in upper)
        is_serial = ("SPRDVCOM" in upper) or ("U2S DIAG" in upper) or ("USBSER" in upper) or ("MODEM" in upper and not is_winusb)
        if is_winusb:
            winusb_infs.append(inf_name)
            if "VID_1782&PID_4D00" in upper:
                has_4d00_winusb = True
            if "VID_1782&PID_4D03" in upper:
                has_4d03_winusb = True
        elif is_serial and ("VID_1782&PID_4D00" in upper or "VID_1782&PID_4D03" in upper):
            conflicting_serial_infs.append(inf_name)

    return {
        "installed": has_4d00_winusb and has_4d03_winusb,
        "has_4d00_winusb": has_4d00_winusb,
        "has_4d03_winusb": has_4d03_winusb,
        "winusb_infs": winusb_infs,
        "conflicting_serial_infs": conflicting_serial_infs,
    }


def inspect_unisoc_drivers() -> dict[str, Any]:
    """Check whether Windows Driver Store already has WinUSB drivers for BOTH 1782:4D00 and 1782:4D03."""
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


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def verify_win64_driver_installer_integrity(
    tools_dir: Path,
    *,
    manifest_path: Path,
    cache_dir: Path,
) -> dict[str, Any]:
    """Bind qmk_driver_installer.exe and unisoc_drivers.txt byte-for-byte to the manifest-verified host-tools-win64.zip."""
    if not manifest_path.is_file():
        return {"ok": False, "error": f"缺少官方资产校验清单：{manifest_path}"}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        pack = (manifest.get("packs") or {}).get("host_tools_win64") or {}
        fname = str(pack.get("filename") or "")
        exp_zip_sha = str(pack.get("sha256") or "").lower()
    except Exception as exc:
        return {"ok": False, "error": f"读取官方资产清单失败：{exc}"}
    if not fname or len(exp_zip_sha) != 64:
        return {"ok": False, "error": "官方资产清单缺少 host_tools_win64 有效 SHA-256"}

    arc_cands = [cache_dir / fname, manifest_path.parents[1] / "dist" / f"release-{manifest.get('release_tag', '')}" / fname]
    arc: Path | None = None
    for cand in arc_cands:
        if cand.is_file() and _sha256_path(cand) == exp_zip_sha:
            arc = cand
            break
    if arc is None:
        return {"ok": False, "error": f"未找到通过官方 SHA-256 校验的 {fname}，拒绝执行未认证的本地驱动安装程序。"}

    qmk_dir = tools_dir / "host-tools-win64" / "qmk_driver_installer"
    installer = qmk_dir / "qmk_driver_installer.exe"
    drv_list = qmk_dir / "unisoc_drivers.txt"
    if not installer.is_file() or not drv_list.is_file():
        return {"ok": False, "error": "驱动安装器或 unisoc_drivers.txt 缺失，请重新拉取并解压 host-tools-win64。"}

    try:
        with zipfile.ZipFile(arc) as zf:
            exp_exe = hashlib.sha256(zf.read("qmk_driver_installer/qmk_driver_installer.exe")).hexdigest()
            exp_txt = hashlib.sha256(zf.read("qmk_driver_installer/unisoc_drivers.txt")).hexdigest()
    except Exception as exc:
        return {"ok": False, "error": f"读取已认证压缩包成员失败：{exc}"}

    if _sha256_path(installer) != exp_exe:
        return {"ok": False, "error": "安全拦截：qmk_driver_installer.exe 与官方认证压缩包哈希不一致，已拒绝提权运行！"}
    if _sha256_path(drv_list) != exp_txt:
        return {"ok": False, "error": "安全拦截：unisoc_drivers.txt 与官方认证压缩包哈希不一致，已拒绝运行！"}
    return {"ok": True, "archive_sha256": exp_zip_sha, "installer_sha256": exp_exe}


def evaluate_driver_install_result(
    *,
    returncode: int,
    output: str,
    driver_store: dict[str, Any],
    live_usb: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Strict verdict for qmk_driver_installer --force --all: BOTH 4D00 & 4D03 must exist in Driver Store and no live binding conflict."""
    low = (output or "").lower()
    output_has_failure = any(
        tok in low
        for tok in (
            "no matching device found",
            "driver installation failed",
            "operation timed out",
            "cancelled by user",
            "canceled by user",
            "access is denied",
        )
    )
    both_in_store = bool(driver_store.get("has_4d00_winusb")) and bool(driver_store.get("has_4d03_winusb"))
    live_conflict = False
    if live_usb:
        if live_usb.get("query_ok") is False:
            live_conflict = True
        elif any(i.get("code") == "BROM_DRIVER_NOT_WINUSB" for i in (live_usb.get("issues") or [])):
            live_conflict = True

    ok = (returncode == 0) and (not output_has_failure) and both_in_store and (not live_conflict)
    reason = ""
    if not ok:
        if returncode != 0:
            reason = f"qmk_driver_installer 返回非零退出码 ({returncode})。"
        elif output_has_failure:
            reason = "驱动安装器输出包含失败或取消提示（请确认已点击驱动安装确认框中的「安装」）。"
        elif not both_in_store:
            reason = (
                f"Windows 驱动库校验未同时找到 1782:4D00 与 1782:4D03 的 WinUSB 驱动"
                f"（4D00={driver_store.get('has_4d00_winusb')}, 4D03={driver_store.get('has_4d03_winusb')}）。"
            )
        elif live_conflict:
            reason = "驱动虽已入库，但实时设备状态查询失败或已连接的 1782:4D00/4D03 设备仍绑定在冲突驱动上，请用 Zadig 替换为 WinUSB。"
    return {"ok": ok, "reason": reason}


def install_unisoc_winusb_drivers(
    tools_dir: Path,
    *,
    manifest_path: Path | None = None,
    cache_dir: Path | None = None,
    log_cb: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Authenticate qmk_driver_installer.exe against manifest zip, run `--force --all`, and strictly verify Driver Store + live binding."""
    qmk_dir = tools_dir / "host-tools-win64" / "qmk_driver_installer"
    installer = qmk_dir / "qmk_driver_installer.exe"
    drv_list = qmk_dir / "unisoc_drivers.txt"
    if not installer.is_file() or not drv_list.is_file():
        return {
            "ok": False,
            "error": "未找到驱动安装器，请先点击「一键拉取并完成全部体检」。",
        }
    if manifest_path is not None and cache_dir is not None:
        integrity = verify_win64_driver_installer_integrity(
            tools_dir, manifest_path=manifest_path, cache_dir=cache_dir
        )
        if not integrity.get("ok"):
            return {"ok": False, "error": str(integrity.get("error"))}
    for p in (installer, drv_list):
        compat = check_native_tool_path_compat(p)
        if not compat["ok"]:
            return {"ok": False, "error": compat["reason"]}
    if not is_windows_admin():
        return {
            "ok": False,
            "error": "需要管理员权限才能安装 Windows 驱动，请右键「以管理员身份运行」本程序。",
        }
    cmd = [str(installer), "--force", "--all", str(drv_list)]
    if log_cb:
        log_cb("正在以 --force --all 离线预装展锐 WinUSB 驱动（1782:4D00 / 1782:4D03）...")
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=150.0,
            **_no_window_kwargs(),
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": "驱动安装超时（150 秒），请检查是否被系统驱动安全确认弹窗阻塞在后台。",
        }
    combined = ((res.stdout or "") + "\n" + (res.stderr or "")).strip()
    if log_cb and combined:
        for line in combined.splitlines():
            log_cb(f"  [driver] {line}")
    post_check = inspect_unisoc_drivers()
    live_usb = detect_usb_device_state(probe_network=False)
    verdict = evaluate_driver_install_result(
        returncode=res.returncode,
        output=combined,
        driver_store=post_check,
        live_usb=live_usb,
    )
    return {
        "ok": verdict["ok"],
        "error": verdict["reason"],
        "returncode": res.returncode,
        "output": combined,
        "driver_store": post_check,
        "live_usb": live_usb,
    }


def _sanitize_webui_identity(raw: dict[str, Any] | None) -> dict[str, str] | None:
    """Strictly classify WebUI identity into known allowlisted MU3356 schema (never echoes arbitrary strings)."""
    if not isinstance(raw, dict):
        return None
    model = str(raw.get("model_name") or "").strip()
    ver = str(raw.get("cr_version") or raw.get("wa_inner_version") or "").strip()
    if not model and not ver:
        return None
    if not model:
        safe_model = ""
    elif model.upper() == "MU3356":
        safe_model = "MU3356"
    elif _SAFE_MODEL_RE.match(model):
        safe_model = model
    else:
        safe_model = "<UNEXPECTED_MODEL>"
    safe_ver = ver if (not ver or re.match(r"^(?:BD_|CR_)?[A-Za-z0-9._-]{4,48}$", ver)) else "<NON_STANDARD_VERSION>"
    return {"model_name": safe_model, "cr_version": safe_ver}


def probe_zte_webui_identity(host: str = "http://192.168.0.1:8080", *, timeout: float = 1.8) -> dict[str, Any] | None:
    """Read-only probe of stock ZTE WebUI identity (bypasses system HTTP proxy and validates output format)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    url = f"{host.rstrip('/')}/goform/goform_get_cmd_process?isTest=false&multi_data=1&cmd=model_name,cr_version,hardware_version,wa_inner_version"
    req = urllib.request.Request(url, headers={"Referer": f"{host.rstrip('/')}/index.html"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            data = json.loads(resp.read(32768).decode("utf-8", errors="replace"))
        return _sanitize_webui_identity(data)
    except Exception:
        return None


def test_webui_password(password: str, host: str = "http://192.168.0.1:8080", *, timeout: float = 3.0) -> dict[str, Any]:
    """Verify stock ZTE WebUI login password read-only using the exact shared `brom_backup.verify_zte_webui_login` logic."""
    if password == "":
        return {"ok": False, "reason": "empty", "message": "请先输入原厂管理后台密码（通常贴在机身背面或 192.168.0.1:8080 登录密码）。"}

    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    from brom_backup import verify_zte_webui_login

    res = verify_zte_webui_login(password, host=host, timeout=timeout)
    if res.get("ok"):
        safe = _sanitize_webui_identity(res) or {"model_name": "MU3356", "cr_version": ""}
        return {
            "ok": True,
            "model_name": safe["model_name"],
            "cr_version": safe["cr_version"],
            "message": f"原厂后台密码验证通过！（机型：{safe['model_name'] or 'MU3356'}，固件：{safe['cr_version']}）",
        }
    reason = res.get("reason", "unknown")
    if reason == "unreachable":
        return {
            "ok": False,
            "reason": "unreachable",
            "message": f"无法连接原厂管理后台 {host.rstrip('/')}（请确认 F50 Pro 已开机插线且在原厂安卓系统）：{res.get('detail', '')}",
        }
    if reason == "wrong_password":
        return {
            "ok": False,
            "reason": "wrong_password",
            "message": f"原厂后台密码错误（result={res.get('result_code', '')}）。请核对机身背面密码或先在浏览器打开 {host.rstrip('/')} 确认登录密码。",
        }
    return {
        "ok": False,
        "reason": str(reason),
        "message": f"原厂后台验证异常：{res.get('detail', reason)}",
    }


def _normalize_pnp_record(dev: dict[str, Any]) -> dict[str, Any]:
    """Normalize Windows CIM (`Win32_PnPEntity`) and `Get-PnpDevice` schemas into one canonical structure."""
    pnp_id = str(dev.get("PNPDeviceID") or dev.get("InstanceId") or "").strip()
    name = str(dev.get("FriendlyName") or dev.get("Name") or "").strip()
    service = str(dev.get("Service") or "").strip()
    raw_err = dev.get("ConfigManagerErrorCode")
    try:
        err_code = int(raw_err) if raw_err is not None else 0
    except (ValueError, TypeError):
        err_code = 0
    return {
        "pnp_id": pnp_id,
        "pnp_upper": pnp_id.upper(),
        "name": name,
        "name_upper": name.upper(),
        "service": service.lower(),
        "error_code": err_code,
    }


def parse_pnp_usb_devices(
    devices: list[dict[str, Any]],
    *,
    webui_info: dict[str, Any] | None = None,
    openwrt_ssh_open: bool = False,
    query_ok: bool = True,
) -> dict[str, Any]:
    """Classify live Windows PnP device list into F50 Pro state and report ALL present modes & binding issues."""
    brom_devs: list[dict[str, Any]] = []
    stock_devs: list[dict[str, Any]] = []
    openwrt_devs: list[dict[str, Any]] = []

    for raw in devices:
        dev = _normalize_pnp_record(raw)
        pnp_u = dev["pnp_upper"]
        if "VID_1782&PID_4D00" in pnp_u or "VID_1782&PID_4D03" in pnp_u:
            brom_devs.append(dev)
        elif "VID_19D2&PID_0246" in pnp_u or "VID_19D2&PID_024" in pnp_u:
            stock_devs.append(dev)
        elif "VID_1D6B&PID_0104" in pnp_u:
            openwrt_devs.append(dev)

    present_modes: list[str] = []
    if brom_devs:
        present_modes.append("brom")
    if openwrt_devs:
        present_modes.append("openwrt")
    if stock_devs:
        present_modes.append("stock_android")

    issues: list[dict[str, str]] = []
    if not query_ok:
        issues.append(
            {
                "code": "PNP_QUERY_FAILED",
                "severity": "error",
                "message": "Windows PnP 设备查询失败，无法确认当前 USB 连接状态（已安全拦截敏感网络还原操作）。",
            }
        )

    if brom_devs:
        allowed_svcs = {"winusb", "libusbk", "libusb0"}
        bad_brom = [d for d in brom_devs if d["error_code"] != 0 or d["service"] not in allowed_svcs]
        if bad_brom:
            bad_svcs = sorted({d["service"] or "未安装" for d in bad_brom})
            issues.append(
                {
                    "code": "BROM_DRIVER_NOT_WINUSB",
                    "severity": "error",
                    "message": f"检测到展锐刷机口 (1782:4D00/4D03)，但存在未绑定 WinUSB 或异常的接口（当前：{', '.join(bad_svcs)}），请点击「一键修驱动」或用 Zadig 替换。",
                }
            )
        return {
            "state": "brom",
            "query_ok": query_ok,
            "present_modes": present_modes,
            "label": "已连接：展锐刷机模式 (1782:4D00 / AutoD)",
            "device_count": len(brom_devs),
            "error_codes": sorted({d["error_code"] for d in brom_devs if d["error_code"] != 0}),
            "issues": issues,
        }

    if openwrt_devs:
        ncm_err = [
            d
            for d in openwrt_devs
            if d["error_code"] != 0
            and ("MI_00" in d["pnp_upper"] or "NCM" in d["name_upper"] or "RNDIS" in d["name_upper"] or "CDC" in d["name_upper"])
        ]
        if ncm_err:
            codes = ",".join(str(d["error_code"]) for d in ncm_err)
            issues.append(
                {
                    "code": "OPENWRT_WIN10_NCM_ERROR",
                    "severity": "warn",
                    "message": f"检测到 OpenWrt USB 网卡 (1D6B:0104) 驱动异常（错误码 {codes}）；刷机配网会自动通过 MI_02 串口切为 RNDIS，也可点击「修复 USB 网卡 + 防断网隔离」。",
                }
            )
        return {
            "state": "openwrt",
            "query_ok": query_ok,
            "present_modes": present_modes,
            "label": f"已连接：F50 Pro OpenWrt ({'SSH 在线 192.168.77.1' if openwrt_ssh_open else '等待网络就绪'})",
            "openwrt_ssh_open": openwrt_ssh_open,
            "device_count": len(openwrt_devs),
            "error_codes": sorted({d["error_code"] for d in openwrt_devs if d["error_code"] != 0}),
            "issues": issues,
        }

    if stock_devs:
        rndis_err = [d for d in stock_devs if d["error_code"] != 0]
        if rndis_err:
            codes = ",".join(str(d["error_code"]) for d in rndis_err)
            issues.append(
                {
                    "code": "STOCK_RNDIS_DRIVER_ERROR",
                    "severity": "error",
                    "message": f"检测到 F50 Pro 原厂设备 (19D2:0246)，但 Windows RNDIS 网卡驱动异常（错误码 {codes}），请换主板后置口或点击「修复 USB 网卡」。",
                }
            )
        safe_web = _sanitize_webui_identity(webui_info)
        model = str((safe_web or {}).get("model_name") or "")
        ver = str((safe_web or {}).get("cr_version") or "")
        if model and model.upper() != "MU3356":
            issues.append(
                {
                    "code": "WRONG_DEVICE_MODEL",
                    "severity": "error",
                    "message": f"危险拦截：检测到机型为 {model}，不是中兴 F50 Pro (MU3356)！严禁跨型号刷机，否则会变砖！",
                }
            )
        elif not safe_web and not rndis_err:
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
            "query_ok": query_ok,
            "present_modes": present_modes,
            "label": label,
            "webui_info": safe_web,
            "device_count": len(stock_devs),
            "error_codes": sorted({d["error_code"] for d in stock_devs if d["error_code"] != 0}),
            "issues": issues,
        }

    if query_ok:
        issues.append(
            {
                "code": "DEVICE_DISCONNECTED",
                "severity": "warn",
                "message": "未检测到 F50 Pro：请换一根确认能传数据的 USB-A 转 Type-C 线，直插电脑主板后置 USB 口（勿用纯充电线/扩展坞），通电等待约 20 秒。",
            }
        )
    return {
        "state": "disconnected" if query_ok else "query_error",
        "query_ok": query_ok,
        "present_modes": present_modes,
        "label": "未检测到 F50 Pro 设备" if query_ok else "USB PnP 查询异常",
        "device_count": 0,
        "error_codes": [],
        "issues": issues,
    }


def detect_usb_device_state(*, probe_network: bool = True) -> dict[str, Any]:
    """Live Windows USB PnP + optional WebUI/SSH radar for F50 Pro (tracks query_ok fail-closed)."""
    devices: list[dict[str, Any]] = []
    query_ok = True
    if sys.platform == "win32":
        ps = (
            "$devs = Get-CimInstance Win32_PnPEntity -ErrorAction Stop | "
            "Where-Object { $_.PNPDeviceID -match 'VID_(1782|19D2|1D6B)' } | "
            "Select-Object Name, PNPDeviceID, Service, Status, ConfigManagerErrorCode; "
            "if ($null -eq $devs) { '[]' } else { @($devs) | ConvertTo-Json -Compress -Depth 3 }"
        )
        try:
            res = _run_powershell(ps, timeout=8.0)
            if res.returncode == 0 and res.stdout.strip():
                parsed = json.loads(res.stdout.strip())
                devices = parsed if isinstance(parsed, list) else [parsed]
            else:
                query_ok = False
        except Exception:
            query_ok = False
            devices = []

    webui_info = None
    openwrt_ssh_open = False
    if probe_network and query_ok:
        has_stock = any("VID_19D2" in str(d.get("PNPDeviceID") or d.get("InstanceId") or "").upper() for d in devices)
        has_ow = any("VID_1D6B&PID_0104" in str(d.get("PNPDeviceID") or d.get("InstanceId") or "").upper() for d in devices)
        if has_stock:
            webui_info = probe_zte_webui_identity()
        if has_ow:
            try:
                with socket.create_connection(("192.168.77.1", 22), timeout=0.6):
                    openwrt_ssh_open = True
            except OSError:
                openwrt_ssh_open = False

    return parse_pnp_usb_devices(devices, webui_info=webui_info, openwrt_ssh_open=openwrt_ssh_open, query_ok=query_ok)


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


def _probe_openwrt_mgmt_port(host: str = "192.168.77.1", timeout: float = 1.2) -> bool:
    for port in (22, 80):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def repair_usb_network_via_worker(
    *,
    run_host_net_fn: Callable[[list[str]], tuple[int, str]],
    snapshot_path: Path | None = None,
    usb_state: dict[str, Any] | None = None,
    probe_openwrt_mgmt_fn: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Mode-aware USB network repair via isolated worker subprocess with nested-JSON parsing & strict postconditions."""
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

    cur = usb_state if usb_state is not None else detect_usb_device_state(probe_network=True)
    state = cur.get("state")

    if state == "stock_android":
        has_err = any(i.get("code") == "STOCK_RNDIS_DRIVER_ERROR" for i in (cur.get("issues") or []))
        web = cur.get("webui_info") or {}
        model_ok = str(web.get("model_name") or "").upper() == "MU3356"
        rc_aud, out_aud = run_host_net_fn(["audit", "--include-zte-android"])
        aud_json = extract_last_json_object(out_aud) or {}
        adapters = aud_json.get("rndis_adapters") or []
        stock_up = [
            a for a in adapters
            if isinstance(a, dict)
            and "VID_19D2&PID_024" in str(a.get("PnpDeviceID") or "").upper()
            and str(a.get("Status") or "").lower() == "up"
        ]
        aud_ok = (
            (rc_aud == 0)
            and (not aud_json.get("query_errors"))
            and (not aud_json.get("audit_incomplete"))
            and (len(stock_up) >= 1)
        )
        if not has_err and model_ok and aud_ok:
            return {
                "ok": True,
                "mode": "stock_android",
                "correlated_stock_adapters": len(stock_up),
                "notes": notes,
                "message": "原厂 F50 Pro (MU3356 / 19D2:0246) RNDIS 网卡已关联在线且 192.168.0.1:8080 后台与路由审计通过。",
            }
        return {
            "ok": False,
            "mode": "stock_android",
            "correlated_stock_adapters": len(stock_up),
            "notes": notes,
            "error": (
                "原厂 19D2:0246 网卡关联、192.168.0.1:8080 后台（MU3356）或路由审计尚未全部就绪。"
                "请更换主板后置 USB 口/数据线，或在设备管理器中将其更新为「Microsoft -> 基于远程 NDIS 的 Internet 共享设备」。"
            ),
        }

    if state == "openwrt":
        rc_bind, out_bind = run_host_net_fn(["bind-rndis"])
        bind_json = extract_last_json_object(out_bind) or {}
        bind_ok = (rc_bind == 0) and (not bind_json.get("error"))

        iso_cmd = ["isolate", "--mode", "management"]
        if snapshot_path is not None:
            iso_cmd += ["--snapshot", str(snapshot_path)]
        rc_iso, out_iso = run_host_net_fn(iso_cmd)
        rc_aud, out_aud = run_host_net_fn(["audit"])

        iso_json = extract_last_json_object(out_iso) or {}
        aud_json = extract_last_json_object(out_aud) or {}

        isolated_list = iso_json.get("isolated")
        iso_targets = len(isolated_list) if isinstance(isolated_list, list) else 0
        iso_target_routes = iso_json.get("target_default_routes")
        iso_qerrs = iso_json.get("query_errors") or []
        readback = iso_json.get("readback")
        readback_ok = (
            isinstance(readback, list)
            and len(readback) >= 1
            and all(
                isinstance(rb, dict)
                and (rb.get("query_ok") is not False)
                and bool(rb.get("ip_ok"))
                and str(rb.get("dhcp") or "").lower() == "disabled"
                and int(rb.get("metric") or 0) == 5000
                and (rb.get("ipv6_enabled") is False)
                and int(rb.get("dns_count") or 0) == 0
                and (rb.get("register_dns") is False)
                for rb in readback
            )
        )
        leak = bool(aud_json.get("usb_default_route_leak", True))
        aud_incomplete = bool(aud_json.get("audit_incomplete", False))
        aud_qerrs = aud_json.get("query_errors") or []

        mgmt_probe = probe_openwrt_mgmt_fn if probe_openwrt_mgmt_fn is not None else _probe_openwrt_mgmt_port
        mgmt_reachable = bool(mgmt_probe()) if (rc_iso == 0 and iso_targets >= 1) else False

        ok = (
            bind_ok
            and (rc_iso == 0)
            and (rc_aud == 0)
            and (iso_targets >= 1)
            and readback_ok
            and (not iso_target_routes)
            and (not iso_qerrs)
            and (not leak)
            and (not aud_incomplete)
            and (not aud_qerrs)
            and mgmt_reachable
        )
        err_parts: list[str] = []
        if not bind_ok:
            err_parts.append(f"bind-rndis 失败 (rc={rc_bind})")
        if rc_iso != 0 or iso_targets < 1:
            err_parts.append(f"未隔离任何 1D6B:0104 网卡 (rc={rc_iso}, isolated={iso_targets})")
        if iso_target_routes or leak or aud_incomplete or iso_qerrs or aud_qerrs:
            err_parts.append("仍检测到默认路由泄露或路由审计不完整")
        if (rc_iso == 0 and iso_targets >= 1) and not mgmt_reachable:
            err_parts.append("网卡已配置为 192.168.77.12/24 防断网隔离，但 192.168.77.1 (SSH/HTTP) 暂不可达，请等待设备启动完毕后重试")
        return {
            "ok": ok,
            "mode": "openwrt",
            "notes": notes,
            "bind_rc": rc_bind,
            "isolate_rc": rc_iso,
            "audit_rc": rc_aud,
            "isolated_count": iso_targets,
            "usb_default_route_leak": leak,
            "mgmt_reachable": mgmt_reachable,
            "message": "OpenWrt (1D6B:0104) 网卡已绑定隔离（192.168.77.12/24 无默认网关）、路由无泄露且 192.168.77.1 管理口连通正常。" if ok else "",
            "error": "" if ok else ("；".join(err_parts) or "未通过 OpenWrt 网卡隔离与连通性全部验收项。"),
        }

    return {
        "ok": False,
        "mode": str(state or "disconnected"),
        "notes": notes,
        "error": "当前未检测到处于原厂安卓 (19D2:0246) 或 OpenWrt (1D6B:0104) 模式的 F50 Pro USB 网卡，请先检查数据线与主板后置 USB 口。",
    }


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
                "点击下方「一键安装/修复展锐驱动」，程序会自动校验安装包并以 --force --all 预装 1782:4D00 与 1782:4D03 驱动并核验入库。",
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
                "先点击密码框旁的「立即验证密码」按钮确认通过，再重新开始。",
            ],
            "fix_action": "focus_webui_password",
            "fix_label": "去核对并验证原厂密码",
        }

    if "stock webui unreachable" in low or ("192.168.0.1:8080" in low and ("unreachable" in low or "timed out" in low or "refused" in low)):
        return {
            "code": "WEBUI_UNREACHABLE",
            "title": "无法连接 F50 Pro 原厂后台 (192.168.0.1:8080)",
            "cause": "电脑未识别到 F50 Pro 的 RNDIS USB 网卡，或数据线仅支持充电，或本机 VPN/代理软件拦截了局域网地址。",
            "steps": [
                "换一根确认能给手机传数据的 USB-A 转 Type-C 线，直插台式机主板后置 USB 口。",
                "点击下方「一键修复 USB 网卡」刷新设备管理器并复核 192.168.0.1:8080 连通性。",
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

    if "target unit identity mismatch" in low or ("unit_identity" in low and "mismatch" in low):
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

    if failure_report or "flash_failure_report.json" in low or "rollback_failure_report.json" in low or ("readback" in low and "mismatch" in low):
        return {
            "code": "FLASH_SAFE_STOP",
            "title": "刷写/读回校验中途安全暂停（未切槽、未盲目重启）",
            "cause": "写入或读回 SHA-256 核验时出现传输中断；工具已原地止损，你的原厂安卓 _a 槽通常完好无损！",
            "steps": [
                "切勿慌张反复插拔断电！先检查 USB 线是否松动并更换主板后置口。",
                "排查完线材后可先重新核对干跑预览再重试，或使用「受控切回原厂安卓 (_a)」安全回退。",
            ],
            "fix_action": "export_diag",
            "fix_label": "导出脱敏诊断报告",
        }

    if any(k in low for k in ("sha-256 mismatch", "sha-256 校验不匹配", "urlerror", "http error", "getaddrinfo failed", "ssl", "connection reset", "winerror 10054", "无法直连官方 github")):
        return {
            "code": "GITHUB_NETWORK_ERROR",
            "title": "GitHub 资源下载失败或网络超时",
            "cause": "当前网络访问 GitHub Releases 不稳定或镜像返回异常；出于安全红线，官方摘要不可达时已拒绝执行未校验代码。",
            "steps": [
                "点击下方「一键切换国内加速镜像」加速拉取固件大包（摘要仍强制按官方清单 SHA-256 校验）。",
                "或手动从浏览器下载压缩包放入 bundle-cache 目录后切到「仅离线本地模式」。",
            ],
            "fix_action": "switch_mirror",
            "fix_label": "一键切换国内加速镜像",
        }

    return {
        "code": "GENERIC_FAILURE",
        "title": "执行遇到异常",
        "cause": "请查看日志末尾红色报错信息，或导出脱敏诊断报告发给群友/开发者快速定位。",
        "steps": [
            "先点击「一键拉取并完成全部体检」确认驱动、设备连接和空间均为绿灯。",
            "点击下方「导出脱敏诊断报告」自动隐藏密码、设备标识与隐私路径后保存为 txt。",
        ],
        "fix_action": "export_diag",
        "fix_label": "导出脱敏诊断报告",
    }


def sanitize_diagnostic_text(
    raw: str,
    *,
    secrets: list[str] | None = None,
    extra_redact_paths: list[str | Path] | None = None,
) -> str:
    """Scrub passwords, tokens, SSIDs, JSON-escaped USB serials, MACs, any IMEI/ICCID/IMSI, and local paths."""
    out = raw or ""
    for sec in secrets or []:
        if sec and len(sec) >= 2:
            out = out.replace(sec, "<REDACTED>")
    for p in extra_redact_paths or []:
        ps = str(p or "").strip()
        if ps and len(ps) >= 3:
            out = out.replace(ps, "<LOCAL_PATH_REDACTED>")
            out = out.replace(ps.replace("\\", "\\\\"), "<LOCAL_PATH_REDACTED>")
            out = out.replace(ps.replace("\\", "/"), "<LOCAL_PATH_REDACTED>")

    # CLI flags & key=value / JSON credential and SSID forms
    out = re.sub(
        r"(--(?:webui-password|wifi-password|root-password|wifi-ssid)\s+)(?:\"[^\"]*\"|'[^']*'|\S+)",
        r"\1<REDACTED>",
        out,
        flags=re.I,
    )
    out = re.sub(
        r'("(?:password|webui_password|wifi_password|root_password|wifi_ssid|ssid|passphrase|secret|token|api_key|authorization|cookie|imei|iccid|imsi|sn|serial|pnp_id|pnpdeviceid|instanceid)"\s*:\s*)"(?:\\.|[^"\\])*"',
        r'\1"<REDACTED>"',
        out,
        flags=re.I,
    )
    out = re.sub(
        r"\b((?:password|passwd|pwd|passphrase|psk|wifi_key|secret|token|api_key|sta_ssid|ssid|imei|meid|iccid|imsi)\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;&'\"]+)",
        r"\1<REDACTED>",
        out,
        flags=re.I,
    )
    out = re.sub(r"\b(Authorization\s*:\s*(?:Bearer|Basic)\s+)\S+", r"\1<REDACTED>", out, flags=re.I)
    out = re.sub(r"\b(Cookie\s*:\s*)[^\r\n]+", r"\1<REDACTED>", out, flags=re.I)
    out = re.sub(r"(https?://)([^:@/\s]+):([^@/\s]+)@", r"\1<USER>:<REDACTED>@", out, flags=re.I)

    # USB instance IDs (raw `\` AND JSON-escaped `\\` AND `/`)
    out = re.sub(
        r"(USB(?:\\{1,2}|/)VID_[0-9A-F]{4}&PID_[0-9A-F]{4}(?:&MI_[0-9A-F]{2})?(?:\\{1,2}|/))[^\s\"',}\]]+",
        r"\1<USB_SERIAL_REDACTED>",
        out,
        flags=re.I,
    )
    # MAC addresses
    out = re.sub(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", "<MAC_REDACTED>", out)
    # User paths & arbitrary non-Windows private drive paths (both `\` and `\\` and `/`)
    out = re.sub(r"([A-Za-z]:(?:\\{1,2}|/)+Users(?:\\{1,2}|/)+)[^/\\\s\"']+", r"\1<USER>", out, flags=re.I)
    out = re.sub(r"(/(?:Users|home)/)[^/\s\"']+", r"\1<USER>", out)
    out = re.sub(
        r"(?<![A-Za-z0-9_])[A-Za-z]:(?:\\{1,2}|/)(?!Windows(?:\b|\\|/))[^\s\"'<>|,;}\]]+",
        "<LOCAL_PATH_REDACTED>",
        out,
        flags=re.I,
    )
    # Any 15-digit numeric IMEI (not restricted to 86-prefix) & 19-20 digit ICCID / 15-digit IMSI
    out = re.sub(r"(?<![0-9a-fA-F])(?:89\d{17,18}|460\d{12})(?![0-9a-fA-F])", "<SIM_ID_REDACTED>", out)
    out = re.sub(r"(?<![0-9a-fA-F.])\d{15}(?![0-9a-fA-F.])", "<IMEI_OR_ID_REDACTED>", out)
    # Cloud / GitHub tokens
    out = re.sub(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{10,}\b", "<TOKEN_REDACTED>", out)
    out = re.sub(r"\b(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{20,})\b", "<TOKEN_REDACTED>", out)
    return out


_TYPED_EVENT_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("DRIVER_VERIFIED", re.compile(r"WinUSB 驱动.*(已就绪|已入库|预装并复核|复核通过)", re.I)),
    ("BACKUP_COMPLETED", re.compile(r"原厂全量备份成功", re.I)),
    ("DRY_RUN_APPROVED", re.compile(r"离线干跑预览通过", re.I)),
    ("FLASH_COMPLETED", re.compile(r"一键刷机、自动配网与端到端验收全部通过", re.I)),
    ("ROLLBACK_RESET_SENT", re.compile(r"发送重启指令", re.I)),
    ("PROBE_PASSED", re.compile(r"只读巡检 PASS", re.I)),
    ("NETWORK_ISOLATED", re.compile(r"网卡.*隔离.*(正常|复核|通过)", re.I)),
    ("NETWORK_RESTORED", re.compile(r"安全恢复.*网卡.*快照", re.I)),
    ("PREPARE_COMPLETED", re.compile(r"全部环境体检通过", re.I)),
)


def extract_typed_diagnostic_events(
    log_lines: list[str] | str,
    *,
    secrets: list[str] | None = None,
    extra_redact_paths: list[str | Path] | None = None,
    max_events: int = 40,
) -> list[dict[str, str]]:
    """Map worker logs strictly to fixed enum event codes (ZERO arbitrary free-form stdout text ever exported)."""
    del secrets, extra_redact_paths
    lines = log_lines.splitlines() if isinstance(log_lines, str) else list(log_lines)
    events: list[dict[str, str]] = []
    for raw_ln in lines:
        ln = raw_ln.strip()
        m = re.match(r"^\[(\d{2}:\d{2}:\d{2})\]\s+\[(OK|WARN|ERR|INFO)\]\s*(.*)$", ln)
        if not m:
            continue
        ts, level, body = m.group(1), m.group(2), m.group(3)
        event_code = ""
        for code, pat in _TYPED_EVENT_RULES:
            if pat.search(body):
                event_code = code
                break
        if not event_code:
            if level == "ERR":
                event_code = f"ERROR_{diagnose_failure(body)['code']}"
            elif level == "WARN":
                event_code = "WARNING_EVENT"
            else:
                continue
        events.append({"time": ts, "level": level, "event_code": event_code})
    return events[-max_events:]


def build_sanitized_diagnostic_report(
    *,
    kit_version: str,
    workspace_dir: Path,
    log_tail: str,
    secrets: list[str] | None = None,
    last_diag: dict[str, Any] | None = None,
) -> str:
    """Collect strict allowlisted host diagnostics + fixed enum event codes (ZERO free-form text or unvalidated values)."""
    driver_info = inspect_unisoc_drivers()
    usb_info = detect_usb_device_state(probe_network=True)
    disk_info = check_disk_space(workspace_dir)
    safe_web = _sanitize_webui_identity(usb_info.get("webui_info"))
    raw_model = (safe_web or {}).get("model_name") or ""
    exported_model = "MU3356" if raw_model == "MU3356" else ("<NON_MU3356_MODEL>" if raw_model else None)
    raw_ver = (safe_web or {}).get("cr_version") or ""
    exported_ver = raw_ver if (raw_ver and re.match(r"^(?:BD_|CR_)?MU3356[A-Za-z0-9._-]{0,36}$", raw_ver)) else ("<OTHER_VERSION>" if raw_ver else None)
    redact_paths: list[str | Path] = [workspace_dir, workspace_dir.parent, Path.home()]
    events = extract_typed_diagnostic_events(log_tail, secrets=secrets, extra_redact_paths=redact_paths)

    payload: dict[str, Any] = {
        "schema_version": 3,
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "is_admin": is_windows_admin(),
        "kit_version": kit_version if re.match(r"^(?:v\d+\.\d+\.\d+|bundled|local)$", str(kit_version or "")) else "<UNKNOWN>",
        "disk": {
            "ok": bool(disk_info.get("ok")),
            "free_gb": disk_info.get("free_gb"),
            "required_gb": disk_info.get("required_gb"),
        },
        "unisoc_drivers": {
            "installed": bool(driver_info.get("installed")),
            "has_4d00_winusb": bool(driver_info.get("has_4d00_winusb")),
            "has_4d03_winusb": bool(driver_info.get("has_4d03_winusb")),
            "winusb_inf_count": len(driver_info.get("winusb_infs") or []),
            "serial_conflict_count": len(driver_info.get("conflicting_serial_infs") or []),
        },
        "usb_radar": {
            "query_ok": bool(usb_info.get("query_ok", True)),
            "state": usb_info.get("state"),
            "present_modes": usb_info.get("present_modes", []),
            "device_count": usb_info.get("device_count", 0),
            "error_codes": usb_info.get("error_codes", []),
            "issue_codes": [i.get("code") for i in (usb_info.get("issues") or [])],
            "webui_model": exported_model,
            "webui_version": exported_ver,
        },
        "last_diagnosis_code": str(last_diag.get("code") or "") if isinstance(last_diag, dict) else None,
        "typed_events": events,
    }
    raw = (
        "=== F50 Pro 一键刷机工具脱敏诊断报告（严格白名单字段 + 固定枚举事件码） ===\n"
        + json.dumps(payload, indent=2, ensure_ascii=False)
        + "\n"
    )
    return sanitize_diagnostic_text(raw, secrets=secrets, extra_redact_paths=redact_paths)
