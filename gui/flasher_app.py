"""Beginner-friendly Windows GUI wizard + embedded `--run-kit` worker for F50 Pro Dual-Boot Kit."""
from __future__ import annotations

import ctypes
import datetime
import json
import os
import queue
import runpy
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path
from typing import Any, Callable

# Ensure repo/bundle root is importable both in source checkout and frozen PyInstaller runtime.
_THIS_FILE = Path(__file__).resolve()
_BUNDLE_ROOT = Path(getattr(sys, "_MEIPASS", _THIS_FILE.parents[1])).resolve()
if str(_BUNDLE_ROOT) not in sys.path:
    sys.path.insert(0, str(_BUNDLE_ROOT))

from gui.diagnostics import (  # noqa: E402
    build_sanitized_diagnostic_report,
    check_disk_space,
    detect_usb_device_state,
    diagnose_failure,
    ensure_adb_pubkey,
    inspect_unisoc_drivers,
    install_unisoc_winusb_drivers,
    is_windows_admin,
    sanitize_diagnostic_text,
    test_webui_password,
    try_repair_usb_network,
)
from gui.github_updater import (  # noqa: E402
    PRESET_MIRRORS,
    download_and_verify_kit_release,
    fetch_latest_release_info,
    normalize_mirror_prefix,
    resolve_kit_version,
)


def app_base_dir() -> Path:
    """Writable directory beside F50Pro-Flasher.exe (or repo root when running from source)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return _THIS_FILE.parents[1]


def bundled_kit_root() -> Path:
    """Return bundled offline fallback kit root (containing scripts/kit.py and assets/)."""
    cand = _BUNDLE_ROOT
    if (cand / "scripts" / "kit.py").is_file():
        return cand
    alt = app_base_dir()
    if (alt / "scripts" / "kit.py").is_file():
        return alt
    return cand


def _dispatch_embedded_script(mode_flag: str, argv: list[str]) -> int:
    """Execute kit.py or host_network.py from an arbitrary (e.g. GitHub-downloaded) kit root using bundled Python."""
    if len(argv) < 2:
        print(f"Usage: {mode_flag} <kit_root> [script args...]", file=sys.stderr)
        return 2
    kit_root = Path(argv[1]).resolve()
    script_name = "kit.py" if mode_flag == "--run-kit" else "host_network.py"
    script_path = kit_root / "scripts" / script_name
    if not script_path.is_file():
        print(f"Script not found: {script_path}", file=sys.stderr)
        return 2

    scripts_dir = str(kit_root / "scripts")
    sys.path.insert(0, scripts_dir)
    os.chdir(str(kit_root))
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
            sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        except Exception:
            pass
    sys.argv = [str(script_path), *argv[2:]]
    try:
        runpy.run_path(str(script_path), run_name="__main__")
        return 0
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        print(str(code), file=sys.stderr)
        return 1


def build_worker_command(mode_flag: str, kit_root: Path, script_args: list[str]) -> list[str]:
    """Build subprocess argv that invokes this app's embedded Python runtime in worker mode."""
    if getattr(sys, "frozen", False):
        return [sys.executable, mode_flag, str(kit_root), *script_args]
    return [sys.executable, str(_THIS_FILE), mode_flag, str(kit_root), *script_args]


def _no_window_kwargs() -> dict[str, Any]:
    if sys.platform == "win32":
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)}
    return {}


def _extract_last_json_object(text: str) -> dict[str, Any] | None:
    """Parse the final JSON object emitted by kit.py stdout."""
    idx = text.rfind("{")
    while idx != -1:
        snippet = text[idx:]
        try:
            obj = json.loads(snippet)
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass
        idx = text.rfind("{", 0, idx)
    return None


def _enable_windows_dpi_awareness() -> None:
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Tkinter GUI Application
# ---------------------------------------------------------------------------


def launch_gui(*, smoke_test: bool = False) -> int:
    _enable_windows_dpi_awareness()

    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk

    PALETTE = {
        "bg": "#F5F7FB",
        "card": "#FFFFFF",
        "border": "#DCE3EE",
        "header": "#162033",
        "header_fg": "#F8FAFC",
        "text": "#1E293B",
        "muted": "#5B6B82",
        "accent": "#2563EB",
        "accent_hover": "#1D4ED8",
        "ok_bg": "#ECFDF5",
        "ok_fg": "#047857",
        "warn_bg": "#FFFBEB",
        "warn_fg": "#B45309",
        "err_bg": "#FEF2F2",
        "err_fg": "#B91C1C",
        "info_bg": "#EFF6FF",
        "info_fg": "#1D4ED8",
    }

    PROFILES_UI: list[tuple[str, str, str]] = [
        (
            "3-dual-full",
            "⭐ 方案 3：双系统全功能（最推荐）",
            "安卓 _a（Magisk Root + UFI-TOOLS + 防劫持）+ OpenWrt 25.12.5 _b（2GB 扩容 + Wi-Fi 中继 + 5 秒物理按键双向热切换）",
        ),
        (
            "2-dual-stock-openwrt",
            "方案 2：原厂安卓零改动 + OpenWrt",
            "安卓 _a 槽 100% 保持原厂不动；OpenWrt 装在 _b 槽（长按按键 5 秒切回原厂安卓）",
        ),
        (
            "1-android-ufi",
            "方案 1：仅安卓 Root + UFI-TOOLS",
            "只给原厂安卓 _a 槽刷入 Magisk 28103 与 UFI-TOOLS 高级管理后台（:2333 / 网页终端 :1146），不装 OpenWrt",
        ),
    ]

    class F50ProFlasherApp:
        def __init__(self, root: tk.Tk, *, smoke_test: bool = False) -> None:
            self.root = root
            self._smoke_test = smoke_test
            self.root.title("中兴 F50 Pro (MU3356) 一键双系统刷机助手")
            self.root.geometry("980x760")
            self.root.minsize(880, 680)
            self.root.configure(bg=PALETTE["bg"])

            self.base_dir = app_base_dir()
            self.workspace_dir = self.base_dir / "workspace"
            self.kit_store_dir = self.workspace_dir / "kit-src"
            self.tools_dir = self.workspace_dir / "runtime-tools"
            self.cache_dir = self.workspace_dir / "bundle-cache"
            self.workspace_dir.mkdir(parents=True, exist_ok=True)
            self.cache_dir.mkdir(parents=True, exist_ok=True)

            # Reuse repo's build/runtime-tools & bundle-cache automatically when running from source checkout
            if not getattr(sys, "frozen", False) and (self.base_dir / "build" / "runtime-tools").is_dir():
                self.tools_dir = self.base_dir / "build" / "runtime-tools"
                if (self.base_dir / "bundle-cache").is_dir():
                    self.cache_dir = self.base_dir / "bundle-cache"

            self.active_kit_root: Path = bundled_kit_root()
            self.active_kit_version: str = resolve_kit_version(self.active_kit_root)
            self._auto_pick_latest_cached_kit()

            self.log_queue: queue.Queue[tuple[str, str]] = queue.Queue()
            self.full_log_lines: list[str] = []
            self.busy = False
            self.active_proc: subprocess.Popen[str] | None = None
            self.active_is_flash = False
            self.last_diag: dict[str, Any] | None = None
            self.last_usb_state: dict[str, Any] = {"state": "unknown", "label": "正在检测 USB 设备...", "issues": []}
            self._radar_running = False
            self._closing = False

            # Form variables
            self.mirror_choice_var = tk.StringVar(value=PRESET_MIRRORS[0][0])
            self.custom_mirror_var = tk.StringVar(value="")
            self.profile_var = tk.StringVar(value="3-dual-full")
            self.openclash_var = tk.BooleanVar(value=True)
            self.webui_pw_var = tk.StringVar(value="")
            self.wifi_ssid_var = tk.StringVar(value="F50Pro-OpenWrt")
            self.wifi_pw_var = tk.StringVar(value="")
            self.gen_root_pw_var = tk.BooleanVar(value=True)
            self.custom_root_pw_var = tk.StringVar(value="")
            self.session_dir_var = tk.StringVar(value=str(self.workspace_dir / "my-f50pro"))
            self.status_step_var = tk.StringVar(value="就绪：请先点击「一键拉取 GitHub 最新版并完成全部体检」")

            self._setup_styles()
            self._build_ui()
            if not self._smoke_test:
                self._poll_log_queue()
                self._refresh_env_cards_async(with_network=False)
                self._schedule_usb_radar()
            self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        def _auto_pick_latest_cached_kit(self) -> None:
            if not self.kit_store_dir.is_dir():
                return
            best: tuple[float, Path, str] | None = None
            for marker in self.kit_store_dir.glob("*/.kit_verified.json"):
                try:
                    rec = json.loads(marker.read_text(encoding="utf-8"))
                    kroot = Path(rec["kit_root"])
                    if (kroot / "scripts" / "kit.py").is_file():
                        mtime = marker.stat().st_mtime
                        if best is None or mtime > best[0]:
                            best = (mtime, kroot, str(rec.get("tag") or marker.parent.name))
                except Exception:
                    continue
            if best:
                self.active_kit_root = best[1]
                self.active_kit_version = best[2]

        def _setup_styles(self) -> None:
            style = ttk.Style(self.root)
            try:
                style.theme_use("vista" if sys.platform == "win32" else "clam")
            except Exception:
                pass
            base_font = ("Microsoft YaHei UI", 10)
            style.configure(".", font=base_font, background=PALETTE["bg"], foreground=PALETTE["text"])
            style.configure("TFrame", background=PALETTE["bg"])
            style.configure("Card.TFrame", background=PALETTE["card"])
            style.configure("TLabel", background=PALETTE["bg"], foreground=PALETTE["text"])
            style.configure("Card.TLabel", background=PALETTE["card"], foreground=PALETTE["text"])
            style.configure("Muted.TLabel", background=PALETTE["card"], foreground=PALETTE["muted"], font=("Microsoft YaHei UI", 9))
            style.configure("Title.TLabel", background=PALETTE["card"], foreground=PALETTE["text"], font=("Microsoft YaHei UI", 11, "bold"))
            style.configure("TNotebook", background=PALETTE["bg"])
            style.configure("TNotebook.Tab", padding=(14, 7), font=("Microsoft YaHei UI", 10, "bold"))
            style.configure("Primary.TButton", font=("Microsoft YaHei UI", 10, "bold"), padding=(14, 8))
            style.configure("Action.TButton", font=("Microsoft YaHei UI", 9, "bold"), padding=(10, 6))
            style.configure("Card.TRadiobutton", background=PALETTE["card"], foreground=PALETTE["text"], font=("Microsoft YaHei UI", 10, "bold"))
            style.configure("Card.TCheckbutton", background=PALETTE["card"], foreground=PALETTE["text"], font=("Microsoft YaHei UI", 10))

        def _make_card(self, parent: tk.Widget, padding: int = 12) -> tk.Frame:
            outer = tk.Frame(parent, bg=PALETTE["card"], highlightbackground=PALETTE["border"], highlightthickness=1)
            inner = tk.Frame(outer, bg=PALETTE["card"], padx=padding, pady=padding)
            inner.pack(fill="both", expand=True)
            outer.inner = inner  # type: ignore[attr-defined]
            return outer

        def _build_ui(self) -> None:
            # --- Top dark banner ---
            hdr = tk.Frame(self.root, bg=PALETTE["header"], padx=18, pady=12)
            hdr.pack(fill="x")

            left_h = tk.Frame(hdr, bg=PALETTE["header"])
            left_h.pack(side="left", fill="x", expand=True)
            tk.Label(
                left_h,
                text="中兴 F50 Pro (MU3356) 一键双系统刷机助手",
                bg=PALETTE["header"],
                fg=PALETTE["header_fg"],
                font=("Microsoft YaHei UI", 14, "bold"),
            ).pack(anchor="w")
            tk.Label(
                left_h,
                text="仅支持中兴 F50 Pro 插卡版(B28) / 双eSIM版(B15) · 自动拉取 GitHub 最新版 · 遇到问题自动排查修复",
                bg=PALETTE["header"],
                fg="#94A3B8",
                font=("Microsoft YaHei UI", 9),
            ).pack(anchor="w", pady=(2, 0))

            right_h = tk.Frame(hdr, bg=PALETTE["header"])
            right_h.pack(side="right")
            self.kit_ver_badge = tk.Label(
                right_h,
                text=f"工具脚本: {self.active_kit_version}",
                bg="#1E3A8A",
                fg="#DBEAFE",
                font=("Microsoft YaHei UI", 9, "bold"),
                padx=10,
                pady=4,
            )
            self.kit_ver_badge.pack(side="left", padx=(0, 8))

            admin_ok = is_windows_admin()
            self.admin_badge = tk.Label(
                right_h,
                text="管理员权限: 已就绪" if admin_ok else "警告: 非管理员运行",
                bg=PALETTE["ok_bg"] if admin_ok else PALETTE["err_bg"],
                fg=PALETTE["ok_fg"] if admin_ok else PALETTE["err_fg"],
                font=("Microsoft YaHei UI", 9, "bold"),
                padx=10,
                pady=4,
            )
            self.admin_badge.pack(side="left")

            # --- Live USB Radar Bar ---
            radar_wrap = tk.Frame(self.root, bg=PALETTE["info_bg"], highlightbackground="#BFDBFE", highlightthickness=1, padx=14, pady=8)
            radar_wrap.pack(fill="x", padx=12, pady=(10, 6))
            self.radar_wrap = radar_wrap

            radar_left = tk.Frame(radar_wrap, bg=PALETTE["info_bg"])
            radar_left.pack(side="left", fill="x", expand=True)
            self.radar_left = radar_left
            self.radar_title_lbl = tk.Label(
                radar_left,
                text="● 正在扫描 USB 设备...",
                bg=PALETTE["info_bg"],
                fg=PALETTE["info_fg"],
                font=("Microsoft YaHei UI", 10, "bold"),
                anchor="w",
            )
            self.radar_title_lbl.pack(fill="x")
            self.radar_hint_lbl = tk.Label(
                radar_left,
                text="请用数据线把 F50 Pro 直连电脑主板 USB 口（无需手动进刷机模式）",
                bg=PALETTE["info_bg"],
                fg=PALETTE["text"],
                font=("Microsoft YaHei UI", 9),
                anchor="w",
            )
            self.radar_hint_lbl.pack(fill="x", pady=(2, 0))

            radar_btns = tk.Frame(radar_wrap, bg=PALETTE["info_bg"])
            radar_btns.pack(side="right", padx=(8, 0))
            self.radar_btns = radar_btns
            ttk.Button(radar_btns, text="刷新设备", style="Action.TButton", command=self._trigger_radar_now).pack(side="left", padx=(0, 6))
            ttk.Button(radar_btns, text="一键修驱动", style="Action.TButton", command=self._action_install_drivers).pack(side="left")

            # --- Main Notebook (4 guided steps) ---
            self.nb = ttk.Notebook(self.root)
            self.nb.pack(fill="both", expand=True, padx=12, pady=4)

            self.tab_env = ttk.Frame(self.nb)
            self.tab_cfg = ttk.Frame(self.nb)
            self.tab_run = ttk.Frame(self.nb)
            self.tab_tools = ttk.Frame(self.nb)

            self.nb.add(self.tab_env, text=" ① 环境体检与自动拉取 ")
            self.nb.add(self.tab_cfg, text=" ② 方案与密码设置 ")
            self.nb.add(self.tab_run, text=" ③ 备份、预览与一键刷机 ")
            self.nb.add(self.tab_tools, text=" ④ 刷后体检与救砖工具 ")

            self._build_tab_env()
            self._build_tab_cfg()
            self._build_tab_run()
            self._build_tab_tools()

            # --- Smart Auto-Troubleshooter Banner (shown automatically on error) ---
            self.diag_frame = tk.Frame(self.root, bg=PALETTE["err_bg"], highlightbackground="#FCA5A5", highlightthickness=1, padx=12, pady=8)
            self.diag_title_lbl = tk.Label(
                self.diag_frame, text="", bg=PALETTE["err_bg"], fg=PALETTE["err_fg"], font=("Microsoft YaHei UI", 10, "bold"), anchor="w"
            )
            self.diag_title_lbl.pack(fill="x")
            self.diag_body_lbl = tk.Label(
                self.diag_frame, text="", bg=PALETTE["err_bg"], fg=PALETTE["text"], font=("Microsoft YaHei UI", 9), justify="left", anchor="w", wraplength=800
            )
            self.diag_body_lbl.pack(fill="x", pady=(2, 6))
            diag_btn_row = tk.Frame(self.diag_frame, bg=PALETTE["err_bg"])
            diag_btn_row.pack(fill="x")
            self.diag_fix_btn = ttk.Button(diag_btn_row, text="一键自动修复", style="Primary.TButton", command=self._run_diag_fix)
            self.diag_fix_btn.pack(side="left", padx=(0, 8))
            ttk.Button(diag_btn_row, text="导出脱敏诊断报告", style="Action.TButton", command=self._action_export_diag).pack(side="left", padx=(0, 8))
            ttk.Button(diag_btn_row, text="关闭提示", command=self._hide_diag_banner).pack(side="right")

            # --- Bottom Progress & Live Log Console ---
            bottom = tk.Frame(self.root, bg=PALETTE["bg"], padx=12, pady=6)
            bottom.pack(fill="x", pady=(0, 4))
            self.bottom_frame = bottom

            prog_row = tk.Frame(bottom, bg=PALETTE["bg"])
            prog_row.pack(fill="x", pady=(0, 4))
            tk.Label(prog_row, textvariable=self.status_step_var, bg=PALETTE["bg"], fg=PALETTE["text"], font=("Microsoft YaHei UI", 9, "bold")).pack(side="left")
            self.stop_btn = ttk.Button(prog_row, text="停止当前任务", command=self._action_stop_task, state="disabled")
            self.stop_btn.pack(side="right", padx=(6, 0))
            ttk.Button(prog_row, text="导出诊断报告", command=self._action_export_diag).pack(side="right", padx=(6, 0))
            ttk.Button(prog_row, text="清空日志", command=self._clear_log).pack(side="right")

            self.progress = ttk.Progressbar(bottom, mode="indeterminate")
            self.progress.pack(fill="x", pady=(0, 6))

            self.log_box = scrolledtext.ScrolledText(
                bottom,
                height=9,
                font=("Consolas", 9),
                bg="#0F172A",
                fg="#E2E8F0",
                insertbackground="#E2E8F0",
                relief="flat",
                padx=8,
                pady=6,
            )
            self.log_box.pack(fill="both", expand=True)
            self.log_box.tag_config("OK", foreground="#34D399")
            self.log_box.tag_config("WARN", foreground="#FBBF24")
            self.log_box.tag_config("ERR", foreground="#F87171")
            self.log_box.tag_config("INFO", foreground="#93C5FD")
            self.log_box.configure(state="disabled")

        def _build_tab_env(self) -> None:
            pad = tk.Frame(self.tab_env, bg=PALETTE["bg"], padx=10, pady=10)
            pad.pack(fill="both", expand=True)

            # Card 1: GitHub source & mirror selector
            c1 = self._make_card(pad)
            c1.pack(fill="x", pady=(0, 10))
            ttk.Label(c1.inner, text="1. GitHub 自动拉取源（下载后强制执行 SHA-256 完整性校验）", style="Title.TLabel").pack(anchor="w")

            row1 = tk.Frame(c1.inner, bg=PALETTE["card"])
            row1.pack(fill="x", pady=(8, 4))
            ttk.Label(row1, text="下载线路：", style="Card.TLabel").pack(side="left")
            cb = ttk.Combobox(
                row1,
                textvariable=self.mirror_choice_var,
                values=[m[0] for m in PRESET_MIRRORS],
                state="readonly",
                width=30,
            )
            cb.pack(side="left", padx=(4, 12))
            ttk.Label(row1, text="自定义 HTTPS 镜像（可选）：", style="Card.TLabel").pack(side="left")
            ttk.Entry(row1, textvariable=self.custom_mirror_var, width=28).pack(side="left", fill="x", expand=True, padx=(4, 0))

            row1b = tk.Frame(c1.inner, bg=PALETTE["card"])
            row1b.pack(fill="x", pady=(4, 0))
            ttk.Label(
                row1b,
                text=f"本地离线包缓存目录：{self.cache_dir}（若网络不通，可手动放压缩包到此目录免下载）",
                style="Muted.TLabel",
            ).pack(side="left")
            ttk.Button(row1b, text="打开缓存目录", command=lambda: self._open_folder(self.cache_dir)).pack(side="right")

            # Card 2: 5 Health check indicators
            c2 = self._make_card(pad)
            c2.pack(fill="x", pady=(0, 10))
            ttk.Label(c2.inner, text="2. 电脑环境自动体检（发现异常会自动修复）", style="Title.TLabel").pack(anchor="w", pady=(0, 6))

            self.env_labels: dict[str, tk.Label] = {}
            checks = [
                ("admin", "管理员权限"),
                ("disk", "磁盘剩余空间 (需 >= 15 GB)"),
                ("kit", "GitHub 最新刷机脚本与固件包"),
                ("driver", "展锐 WinUSB 驱动 (1782:4D00 & 4D03)"),
                ("adbkey", "本机 ADB RSA 密钥 (adbkey.pub)"),
            ]
            for key, name in checks:
                r = tk.Frame(c2.inner, bg=PALETTE["card"])
                r.pack(fill="x", pady=3)
                tk.Label(r, text=f"• {name}：", bg=PALETTE["card"], fg=PALETTE["text"], width=34, anchor="w", font=("Microsoft YaHei UI", 9, "bold")).pack(side="left")
                lbl = tk.Label(r, text="检测中...", bg=PALETTE["card"], fg=PALETTE["muted"], anchor="w", font=("Microsoft YaHei UI", 9))
                lbl.pack(side="left", fill="x", expand=True)
                self.env_labels[key] = lbl

            # Action bar
            act = tk.Frame(pad, bg=PALETTE["bg"])
            act.pack(fill="x", pady=(4, 0))
            self.btn_prepare = ttk.Button(
                act,
                text="🚀 一键拉取 GitHub 最新版并完成全部体检（推荐点这里）",
                style="Primary.TButton",
                command=self._action_full_prepare,
            )
            self.btn_prepare.pack(side="left", padx=(0, 8))
            ttk.Button(act, text="仅刷新体检状态", style="Action.TButton", command=lambda: self._refresh_env_cards_async(with_network=False)).pack(side="left", padx=(0, 8))
            ttk.Button(act, text="下一步：选方案 →", style="Action.TButton", command=lambda: self.nb.select(self.tab_cfg)).pack(side="right")

        def _build_tab_cfg(self) -> None:
            pad = tk.Frame(self.tab_cfg, bg=PALETTE["bg"], padx=10, pady=10)
            pad.pack(fill="both", expand=True)

            # Profile selection card
            c1 = self._make_card(pad)
            c1.pack(fill="x", pady=(0, 10))
            ttk.Label(c1.inner, text="1. 选择刷机方案（3 选 1）", style="Title.TLabel").pack(anchor="w", pady=(0, 6))
            for pid, title, desc in PROFILES_UI:
                rb = ttk.Radiobutton(c1.inner, text=title, value=pid, variable=self.profile_var, style="Card.TRadiobutton")
                rb.pack(anchor="w", pady=(2, 0))
                ttk.Label(c1.inner, text="    " + desc, style="Muted.TLabel").pack(anchor="w", pady=(0, 4))

            ttk.Checkbutton(
                c1.inner,
                text="同时安装干净离线 OpenClash（仅含空模板，不含任何个人节点与订阅，方案 2 / 3 生效）",
                variable=self.openclash_var,
                style="Card.TCheckbutton",
            ).pack(anchor="w", pady=(4, 0))

            # Credentials & paths card
            c2 = self._make_card(pad)
            c2.pack(fill="x", pady=(0, 10))
            ttk.Label(c2.inner, text="2. 密码与备份路径设置", style="Title.TLabel").pack(anchor="w", pady=(0, 8))

            # WebUI Password
            r1 = tk.Frame(c2.inner, bg=PALETTE["card"])
            r1.pack(fill="x", pady=4)
            ttk.Label(r1, text="原厂后台密码 (192.168.0.1:8080)：", style="Card.TLabel", width=30).pack(side="left")
            self.webui_pw_entry = ttk.Entry(r1, textvariable=self.webui_pw_var, show="*", width=26)
            self.webui_pw_entry.pack(side="left", padx=(0, 8))
            ttk.Button(r1, text="立即验证密码（不重启）", style="Action.TButton", command=self._action_test_webui_pw).pack(side="left", padx=(0, 6))
            self.webui_pw_status = tk.Label(r1, text="机身背面贴纸密码", bg=PALETTE["card"], fg=PALETTE["muted"], font=("Microsoft YaHei UI", 9))
            self.webui_pw_status.pack(side="left")

            # OpenWrt Wi-Fi SSID & Password
            r2 = tk.Frame(c2.inner, bg=PALETTE["card"])
            r2.pack(fill="x", pady=4)
            ttk.Label(r2, text="OpenWrt 热点名称 (SSID)：", style="Card.TLabel", width=30).pack(side="left")
            ttk.Entry(r2, textvariable=self.wifi_ssid_var, width=22).pack(side="left", padx=(0, 14))
            ttk.Label(r2, text="热点密码 (至少 8 位)：", style="Card.TLabel").pack(side="left")
            ttk.Entry(r2, textvariable=self.wifi_pw_var, width=20).pack(side="left", padx=(4, 0))

            # OpenWrt Root Password
            r3 = tk.Frame(c2.inner, bg=PALETTE["card"])
            r3.pack(fill="x", pady=4)
            ttk.Checkbutton(
                r3,
                text="自动生成高强度随机 OpenWrt 管理员密码（强烈推荐，刷完自动保存到本机文件）",
                variable=self.gen_root_pw_var,
                style="Card.TCheckbutton",
                command=self._toggle_root_pw_entry,
            ).pack(side="left")
            self.custom_root_pw_entry = ttk.Entry(r3, textvariable=self.custom_root_pw_var, show="*", width=18, state="disabled")
            self.custom_root_pw_entry.pack(side="right")

            # Work / Backup directory
            r4 = tk.Frame(c2.inner, bg=PALETTE["card"])
            r4.pack(fill="x", pady=4)
            ttk.Label(r4, text="本机备份与工作目录 (需 >= 15GB)：", style="Card.TLabel", width=30).pack(side="left")
            ttk.Entry(r4, textvariable=self.session_dir_var, width=42).pack(side="left", fill="x", expand=True, padx=(0, 8))
            ttk.Button(r4, text="选择目录...", command=self._choose_session_dir).pack(side="left")

            nav = tk.Frame(pad, bg=PALETTE["bg"])
            nav.pack(fill="x", pady=(4, 0))
            ttk.Button(nav, text="← 上一步", command=lambda: self.nb.select(self.tab_env)).pack(side="left")
            ttk.Button(nav, text="下一步：备份与一键刷机 →", style="Primary.TButton", command=lambda: self.nb.select(self.tab_run)).pack(side="right")

        def _build_tab_run(self) -> None:
            pad = tk.Frame(self.tab_run, bg=PALETTE["bg"], padx=10, pady=10)
            pad.pack(fill="both", expand=True)

            # Safety Notice
            warn = tk.Frame(pad, bg=PALETTE["warn_bg"], highlightbackground="#FCD34D", highlightthickness=1, padx=12, pady=8)
            warn.pack(fill="x", pady=(0, 10))
            tk.Label(
                warn,
                text="安全红线：全程禁止拔线或断电！工具永不触碰 IMEI/校准/基带/用户数据分区，写入出错会自动原地暂停且不盲目重启。",
                bg=PALETTE["warn_bg"],
                fg=PALETTE["warn_fg"],
                font=("Microsoft YaHei UI", 9, "bold"),
                anchor="w",
            ).pack(fill="x")

            # 3-Step cards
            c1 = self._make_card(pad)
            c1.pack(fill="x", pady=(0, 8))
            r1 = tk.Frame(c1.inner, bg=PALETTE["card"])
            r1.pack(fill="x")
            left1 = tk.Frame(r1, bg=PALETTE["card"])
            left1.pack(side="left", fill="x", expand=True)
            ttk.Label(left1, text="步骤 A：全量只读备份原厂闪存（约 2~5 分钟，零风险）", style="Title.TLabel").pack(anchor="w")
            ttk.Label(left1, text="自动重启进下载口读取本机全部原厂分区并校验 SHA-256，备份完自动重启回原系统。", style="Muted.TLabel").pack(anchor="w")
            ttk.Button(r1, text="打开备份目录", command=lambda: self._open_folder(Path(self.session_dir_var.get()) / "backup")).pack(side="right", padx=(6, 0))
            ttk.Button(r1, text="① 只读备份原厂分区", style="Action.TButton", command=self._action_backup_only).pack(side="right")

            c2 = self._make_card(pad)
            c2.pack(fill="x", pady=(0, 8))
            r2 = tk.Frame(c2.inner, bg=PALETTE["card"])
            r2.pack(fill="x")
            left2 = tk.Frame(r2, bg=PALETTE["card"])
            left2.pack(side="left", fill="x", expand=True)
            ttk.Label(left2, text="步骤 B：100% 离线干跑预览（不联网、不重启、不写设备）", style="Title.TLabel").pack(anchor="w")
            ttk.Label(left2, text="基于本机备份离线派生去 AVB 镜像与写入清单，确认受保护分区写入数为 0。", style="Muted.TLabel").pack(anchor="w")
            ttk.Button(r2, text="② 生成干跑预览", style="Action.TButton", command=self._action_dry_run_plan).pack(side="right")

            c3 = self._make_card(pad)
            c3.pack(fill="x", pady=(0, 8))
            r3 = tk.Frame(c3.inner, bg=PALETTE["card"])
            r3.pack(fill="x")
            left3 = tk.Frame(r3, bg=PALETTE["card"])
            left3.pack(side="left", fill="x", expand=True)
            ttk.Label(left3, text="步骤 C：正式一键刷入与自动配网（约 5~10 分钟）", style="Title.TLabel").pack(anchor="w")
            ttk.Label(
                left3,
                text="若尚未备份则自动在单次会话中先备份再刷写（零中途插拔）；写完逐分区读回 SHA-256 核对，自动配网并隔离电脑防断网。",
                style="Muted.TLabel",
            ).pack(anchor="w")
            self.btn_execute = ttk.Button(r3, text="🚀 ③ 开始一键刷入", style="Primary.TButton", command=self._action_execute_auto)
            self.btn_execute.pack(side="right")

            # Post-flash quick links
            c4 = self._make_card(pad, padding=10)
            c4.pack(fill="x")
            r4 = tk.Frame(c4.inner, bg=PALETTE["card"])
            r4.pack(fill="x")
            ttk.Label(r4, text="刷完快捷入口：", style="Title.TLabel").pack(side="left", padx=(0, 10))
            ttk.Button(r4, text="打开 OpenWrt 后台 (192.168.77.1)", command=lambda: webbrowser.open("http://192.168.77.1")).pack(side="left", padx=(0, 6))
            ttk.Button(r4, text="查看生成的密码文件", command=self._action_show_credentials).pack(side="left", padx=(0, 6))
            ttk.Button(r4, text="打开工作目录", command=lambda: self._open_folder(Path(self.session_dir_var.get()))).pack(side="left")

        def _build_tab_tools(self) -> None:
            pad = tk.Frame(self.tab_tools, bg=PALETTE["bg"], padx=10, pady=10)
            pad.pack(fill="both", expand=True)

            c1 = self._make_card(pad)
            c1.pack(fill="x", pady=(0, 10))
            ttk.Label(c1.inner, text="1. 刷后只读巡检 & 电脑防断网网卡管理", style="Title.TLabel").pack(anchor="w", pady=(0, 8))
            row1 = tk.Frame(c1.inner, bg=PALETTE["card"])
            row1.pack(fill="x")
            ttk.Button(row1, text="一键只读体检 (probe)", style="Action.TButton", command=self._action_probe).pack(side="left", padx=(0, 8))
            ttk.Button(row1, text="修复 USB 网卡 + 防断网隔离", style="Action.TButton", command=self._action_repair_usb_net).pack(side="left", padx=(0, 8))
            ttk.Button(row1, text="电脑走 F50 Pro 5G 上网", command=lambda: self._action_host_net(["isolate", "--mode", "internet-exit"])).pack(side="left", padx=(0, 8))
            ttk.Button(row1, text="恢复隔离前原网卡配置", command=self._action_restore_host_net).pack(side="left")

            c2 = self._make_card(pad)
            c2.pack(fill="x", pady=(0, 10))
            ttk.Label(c2.inner, text="2. 应急切回原厂安卓 (_a 槽) / 排障工具", style="Title.TLabel").pack(anchor="w", pady=(0, 6))
            ttk.Label(
                c2.inner,
                text="如果刷入后想切回原厂安卓：正常运行时长按机身按键 5 秒即可；若进不去系统但能进下载口，可用下方按钮写回本机原始 misc_rollback_a.bin。",
                style="Muted.TLabel",
            ).pack(anchor="w", pady=(0, 8))
            row2 = tk.Frame(c2.inner, bg=PALETTE["card"])
            row2.pack(fill="x")
            ttk.Button(row2, text="通过下载口切回原厂安卓 (_a)", style="Action.TButton", command=self._action_rollback_a).pack(side="left", padx=(0, 8))
            ttk.Button(row2, text="重装展锐 WinUSB 驱动 (--force --all)", command=self._action_install_drivers).pack(side="left", padx=(0, 8))
            ttk.Button(row2, text="导出脱敏诊断报告 (.txt)", command=self._action_export_diag).pack(side="left")

        # ------------------------------------------------------------------
        # Logging, Secrets & Diagnostics UI helpers
        # ------------------------------------------------------------------
        def _active_secrets(self) -> list[str]:
            return [s for s in (self.webui_pw_var.get(), self.wifi_pw_var.get(), self.custom_root_pw_var.get()) if s]

        def log(self, msg: str, tag: str = "") -> None:
            clean = sanitize_diagnostic_text(msg, secrets=self._active_secrets())
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            line = f"[{ts}] {clean}"
            self.log_queue.put((line, tag))

        def _poll_log_queue(self) -> None:
            if self._closing:
                return
            try:
                while True:
                    line, tag = self.log_queue.get_nowait()
                    self.full_log_lines.append(line)
                    if len(self.full_log_lines) > 3000:
                        self.full_log_lines = self.full_log_lines[-2000:]
                    self.log_box.configure(state="normal")
                    if tag:
                        self.log_box.insert("end", line + "\n", tag)
                    else:
                        low = line.lower()
                        auto_tag = ""
                        if "[ok]" in low or '"overall_status": "pass"' in low or '"checks_passed": true' in low:
                            auto_tag = "OK"
                        elif "[err]" in low or "error" in low or "failed" in low or "traceback" in low:
                            auto_tag = "ERR"
                        elif "[warn]" in low or "waiting for" in low:
                            auto_tag = "WARN"
                        self.log_box.insert("end", line + "\n", auto_tag)
                    self.log_box.see("end")
                    self.log_box.configure(state="disabled")
            except queue.Empty:
                pass
            self.root.after(80, self._poll_log_queue)

        def _clear_log(self) -> None:
            self.full_log_lines.clear()
            self.log_box.configure(state="normal")
            self.log_box.delete("1.0", "end")
            self.log_box.configure(state="disabled")

        def _set_busy(self, is_busy: bool, step_text: str = "", *, is_flash: bool = False) -> None:
            self.busy = is_busy
            self.active_is_flash = is_flash if is_busy else False
            if step_text:
                self.status_step_var.set(step_text)
            if is_busy:
                self.progress.start(12)
                self.stop_btn.configure(state="normal")
            else:
                self.progress.stop()
                self.stop_btn.configure(state="disabled")

        def _show_diag_banner(self, diag: dict[str, Any]) -> None:
            self.last_diag = diag
            self.diag_title_lbl.configure(text=f"自动排查诊断：{diag['title']}")
            steps_txt = "\n".join(f"  {i}. {s}" for i, s in enumerate(diag.get("steps") or [], 1))
            self.diag_body_lbl.configure(text=f"原因：{diag['cause']}\n建议操作：\n{steps_txt}")
            self.diag_fix_btn.configure(text=diag.get("fix_label") or "一键修复")
            self.diag_frame.pack(fill="x", padx=12, pady=(4, 2), before=self.bottom_frame)

        def _hide_diag_banner(self) -> None:
            self.diag_frame.pack_forget()

        def _run_diag_fix(self) -> None:
            if not self.last_diag:
                return
            action = self.last_diag.get("fix_action")
            self._hide_diag_banner()
            if action == "install_drivers":
                self._action_install_drivers()
            elif action == "focus_webui_password":
                self.nb.select(self.tab_cfg)
                self.webui_pw_entry.focus_set()
            elif action == "repair_usb_network":
                self._action_repair_usb_net()
            elif action == "generate_adb_key":
                self._action_generate_adb_key()
            elif action == "switch_mirror":
                cur = self.mirror_choice_var.get()
                if cur == PRESET_MIRRORS[1][0]:
                    self.mirror_choice_var.set(PRESET_MIRRORS[2][0])
                else:
                    self.mirror_choice_var.set(PRESET_MIRRORS[1][0])
                self.nb.select(self.tab_env)
                self.log(f"[INFO] 已自动切换镜像源为：{self.mirror_choice_var.get()}，准备重试拉取。", "INFO")
                self._action_full_prepare()
            elif action == "new_workdir":
                base = Path(self.session_dir_var.get())
                stamp = datetime.datetime.now().strftime("%H%M%S")
                new_dir = base.parent / f"my-f50pro-{stamp}"
                self.session_dir_var.set(str(new_dir))
                self.log(f"[OK] 已切换至全新独立设备工作目录：{new_dir}", "OK")
                self.nb.select(self.tab_run)
            else:
                self._action_export_diag()

        # ------------------------------------------------------------------
        # Mirror & Environment helpers
        # ------------------------------------------------------------------
        def _selected_mirror_prefix(self) -> str:
            custom = self.custom_mirror_var.get().strip()
            if custom:
                return normalize_mirror_prefix(custom)
            label = self.mirror_choice_var.get()
            for name, val in PRESET_MIRRORS:
                if name == label:
                    return val
            return ""

        def _worker_env(self) -> dict[str, str]:
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            env["PYTHONIOENCODING"] = "utf-8"
            mirror = self._selected_mirror_prefix()
            if mirror and mirror != "__OFFLINE__":
                env["F50PRO_GITHUB_MIRROR"] = mirror
            else:
                env.pop("F50PRO_GITHUB_MIRROR", None)
            return env

        def _toggle_root_pw_entry(self) -> None:
            self.custom_root_pw_entry.configure(state="disabled" if self.gen_root_pw_var.get() else "normal")

        def _choose_session_dir(self) -> None:
            chosen = filedialog.askdirectory(initialdir=str(self.workspace_dir), title="选择备份与工作目录（建议预留 >= 15 GB 空间）")
            if chosen:
                self.session_dir_var.set(chosen)
                self._refresh_env_cards_async(with_network=False)

        def _open_folder(self, path: Path) -> None:
            path.mkdir(parents=True, exist_ok=True)
            try:
                if sys.platform == "win32":
                    os.startfile(str(path))  # type: ignore[attr-defined]
                else:
                    webbrowser.open(path.as_uri())
            except Exception as exc:
                messagebox.showerror("无法打开文件夹", str(exc))

        # ------------------------------------------------------------------
        # Live USB Radar (background poll every 2.5s when idle)
        # ------------------------------------------------------------------
        def _schedule_usb_radar(self) -> None:
            if self._closing:
                return
            if not self.busy and not self._radar_running:
                self._trigger_radar_now()
            self.root.after(2800, self._schedule_usb_radar)

        def _trigger_radar_now(self) -> None:
            if self._radar_running:
                return
            self._radar_running = True

            def worker() -> None:
                try:
                    info = detect_usb_device_state(probe_network=True)
                except Exception as exc:
                    info = {"state": "error", "label": f"USB 检测异常: {exc}", "issues": []}
                finally:
                    self._radar_running = False
                if not self._closing:
                    self.root.after(0, lambda: self._apply_usb_radar(info))

            threading.Thread(target=worker, daemon=True).start()

        def _apply_usb_radar(self, info: dict[str, Any]) -> None:
            self.last_usb_state = info
            state = info.get("state")
            issues = info.get("issues") or []
            has_err = any(i.get("severity") == "error" for i in issues)
            wrong_model = any(i.get("code") == "WRONG_DEVICE_MODEL" for i in issues)

            if wrong_model or has_err:
                bg, fg, border = PALETTE["err_bg"], PALETTE["err_fg"], "#FCA5A5"
            elif state in ("stock_android", "openwrt", "brom") and not issues:
                bg, fg, border = PALETTE["ok_bg"], PALETTE["ok_fg"], "#6EE7B7"
            elif state == "disconnected":
                bg, fg, border = PALETTE["warn_bg"], PALETTE["warn_fg"], "#FCD34D"
            else:
                bg, fg, border = PALETTE["info_bg"], PALETTE["info_fg"], "#BFDBFE"

            for w in (self.radar_wrap, self.radar_left, self.radar_btns):
                w.configure(bg=bg)
            self.radar_wrap.configure(highlightbackground=border)
            self.radar_title_lbl.configure(text=f"● {info.get('label', '')}", bg=bg, fg=fg)
            if issues:
                self.radar_hint_lbl.configure(text=issues[0].get("message", ""), bg=bg, fg=PALETTE["text"])
            elif state == "stock_android":
                self.radar_hint_lbl.configure(text="原厂后台在线，可直接验证密码并开始备份/一键刷机。", bg=bg, fg=PALETTE["text"])
            elif state == "openwrt":
                self.radar_hint_lbl.configure(text="OpenWrt 在线，可打开 http://192.168.77.1 或在「刷后体检」中一键检测。", bg=bg, fg=PALETTE["text"])
            elif state == "brom":
                self.radar_hint_lbl.configure(text="已处于展锐刷机口且驱动正常，可直接执行刷写或回退。", bg=bg, fg=PALETTE["text"])

            self.btn_execute.configure(state="disabled" if wrong_model else "normal")

        # ------------------------------------------------------------------
        # Environment Cards Refresh
        # ------------------------------------------------------------------
        def _refresh_env_cards_async(self, *, with_network: bool = False) -> None:
            def worker() -> None:
                admin = is_windows_admin()
                disk = check_disk_space(Path(self.session_dir_var.get()))
                drv = inspect_unisoc_drivers()
                adb_pub = (Path.home() / ".android" / "adbkey.pub").is_file()
                spd_ok = (self.tools_dir / "host-tools-win64" / "spd_dump_251" / "spd_dump.exe").is_file()
                if not self._closing:
                    self.root.after(0, lambda: self._render_env_cards(admin, disk, drv, adb_pub, spd_ok))

            threading.Thread(target=worker, daemon=True).start()

        def _render_env_cards(
            self, admin: bool, disk: dict[str, Any], drv: dict[str, Any], adb_pub: bool, spd_ok: bool
        ) -> None:
            self.kit_ver_badge.configure(text=f"工具脚本: {self.active_kit_version}")
            self.env_labels["admin"].configure(
                text="通过（已获得管理员权限）" if admin else "未通过：请关闭程序并右键「以管理员身份运行」",
                fg=PALETTE["ok_fg"] if admin else PALETTE["err_fg"],
            )
            self.env_labels["disk"].configure(
                text=f"{'通过' if disk['ok'] else '空间不足'}：当前剩余 {disk['free_gb']} GB（{disk['path']}）",
                fg=PALETTE["ok_fg"] if disk["ok"] else PALETTE["err_fg"],
            )
            self.env_labels["kit"].configure(
                text=(
                    f"已就绪（{self.active_kit_version}，Windows 工具包已解压）"
                    if spd_ok
                    else f"待拉取（当前本地回退版 {self.active_kit_version}，点击下方一键拉取最新工具与固件包）"
                ),
                fg=PALETTE["ok_fg"] if spd_ok else PALETTE["warn_fg"],
            )
            conflicts = drv.get("conflicting_serial_infs") or []
            if drv.get("installed") and not conflicts:
                drv_txt, drv_fg = f"已预装 WinUSB ({', '.join(drv.get('winusb_infs') or ['OK'])})", PALETTE["ok_fg"]
            elif drv.get("installed") and conflicts:
                drv_txt = f"WinUSB 已装，但检测到旧串口驱动可能冲突 ({', '.join(conflicts)})，刷机如超时请用 Zadig 替换"
                drv_fg = PALETTE["warn_fg"]
            else:
                drv_txt = "尚未安装（点击一键体检将自动使用 --force --all 离线预装）"
                drv_fg = PALETTE["warn_fg"]
            self.env_labels["driver"].configure(text=drv_txt, fg=drv_fg)
            self.env_labels["adbkey"].configure(
                text="已就绪 (~/.android/adbkey.pub)" if adb_pub else "尚未生成（点击一键体检将自动生成）",
                fg=PALETTE["ok_fg"] if adb_pub else PALETTE["warn_fg"],
            )

        # ------------------------------------------------------------------
        # Subprocess Runner
        # ------------------------------------------------------------------
        def _run_subprocess_streaming(self, cmd: list[str], *, env: dict[str, str] | None = None) -> tuple[int, str]:
            out_lines: list[str] = []
            self.active_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env or self._worker_env(),
                **_no_window_kwargs(),
            )
            assert self.active_proc.stdout is not None
            for raw in self.active_proc.stdout:
                line = raw.rstrip("\r\n")
                out_lines.append(line)
                self.log(line)
            rc = self.active_proc.wait()
            self.active_proc = None
            return rc, "\n".join(out_lines)

        def _launch_bg_task(self, title: str, fn: Callable[[], None], *, is_flash: bool = False) -> None:
            if self.busy:
                messagebox.showwarning("任务进行中", "当前已有任务在执行，请等待完成或先点击停止。")
                return
            self._hide_diag_banner()
            self._set_busy(True, title, is_flash=is_flash)

            def wrapper() -> None:
                try:
                    fn()
                except Exception as exc:
                    err_text = str(exc)
                    self.log(f"[ERR] {err_text}", "ERR")
                    diag = diagnose_failure(err_text + "\n" + "\n".join(self.full_log_lines[-40:]))
                    if not self._closing:
                        self.root.after(0, lambda: self._show_diag_banner(diag))
                finally:
                    if not self._closing:
                        self.root.after(0, lambda: self._set_busy(False, "就绪"))
                        self._refresh_env_cards_async(with_network=False)

            threading.Thread(target=wrapper, daemon=True).start()

        def _action_stop_task(self) -> None:
            if not self.active_proc:
                return
            if self.active_is_flash:
                ok = messagebox.askyesno(
                    "高危警告",
                    "当前正处于刷机阶段，强行中断可能停留在下载模式！\n确定要终止进程吗？（切勿同时拔掉 USB 线）",
                )
                if not ok:
                    return
            try:
                self.active_proc.terminate()
                self.log("[WARN] 用户已请求终止当前子进程。", "WARN")
            except Exception as exc:
                self.log(f"[ERR] 停止进程失败：{exc}", "ERR")

        # ------------------------------------------------------------------
        # User Actions
        # ------------------------------------------------------------------
        def _action_full_prepare(self) -> None:
            def task() -> None:
                mirror = self._selected_mirror_prefix()
                offline = mirror == "__OFFLINE__"

                if not is_windows_admin():
                    self.log("[WARN] 当前非管理员权限，安装展锐驱动和网卡隔离可能受限，建议右键以管理员身份运行！", "WARN")

                disk = check_disk_space(Path(self.session_dir_var.get()))
                if not disk["ok"]:
                    raise RuntimeError(f"磁盘剩余空间不足：{disk['path']} 仅剩 {disk['free_gb']} GB，至少需要 15 GB。")

                # 1. Auto-pull latest GitHub Release source (strict SHA-256) unless offline
                if offline:
                    self.log(f"[INFO] 当前为离线模式，使用本地工具脚本：{self.active_kit_root} ({self.active_kit_version})", "INFO")
                else:
                    self.log("正在检查 GitHub 最新稳定版 (tanjiu90/f50pro-dualboot-kit)...", "INFO")
                    try:
                        rel = fetch_latest_release_info(mirror_prefix=mirror)
                        self.log(f"[OK] 检测到 GitHub 最新版本：{rel['tag']} ({rel['name']})", "OK")
                        dl = download_and_verify_kit_release(
                            rel,
                            kit_store_dir=self.kit_store_dir,
                            mirror_prefix=mirror,
                            log_cb=self.log,
                        )
                        self.active_kit_root = Path(dl["kit_root"])
                        self.active_kit_version = str(dl["tag"])
                    except Exception as exc:
                        self.log(f"[WARN] 无法拉取 GitHub 最新版（自动回退到当前已校验版本 {self.active_kit_version}）：{exc}", "WARN")
                        if not (self.tools_dir / "host-tools-win64" / "spd_dump_251" / "spd_dump.exe").is_file():
                            raise

                # 2. Fetch & SHA-256 verify required Windows tools + selected profile firmware packs
                prof = self.profile_var.get()
                args = [
                    "fetch-assets",
                    "--host-platform",
                    "win64",
                    "--profile",
                    prof,
                    "--cache-dir",
                    str(self.cache_dir),
                    "--tools-dir",
                    str(self.tools_dir),
                ]
                if not self.openclash_var.get():
                    args.append("--no-openclash")
                if offline:
                    args.append("--offline-only")
                self.log(f"正在校验并解压所需工具包与固件包（方案：{prof}）...", "INFO")
                rc, out = self._run_subprocess_streaming(build_worker_command("--run-kit", self.active_kit_root, args))
                if rc != 0:
                    raise RuntimeError(f"资源包拉取或校验失败（exit={rc}）：\n{out[-1200:]}")

                # 3. Auto-install Unisoc WinUSB drivers (--force --all) if missing
                drv = inspect_unisoc_drivers()
                if drv.get("installed"):
                    self.log(f"[OK] 展锐 WinUSB 驱动已就绪：{drv.get('winusb_infs')}", "OK")
                else:
                    res = install_unisoc_winusb_drivers(self.tools_dir, log_cb=self.log)
                    if not res.get("ok"):
                        raise RuntimeError(res.get("error") or f"展锐 WinUSB 驱动安装未成功：{res.get('output', '')}")
                    self.log("[OK] 展锐 WinUSB 驱动（1782:4D00 & 4D03）离线预装成功！", "OK")

                # 4. Auto-generate ADB keypair
                adb_res = ensure_adb_pubkey(self.tools_dir)
                if not adb_res.get("ok"):
                    raise RuntimeError(str(adb_res.get("error")))
                self.log(f"[OK] ADB 公钥已就绪：{adb_res['path']}", "OK")

                # 5. Strict preflight verification
                pf_args = [
                    "preflight",
                    "--strict",
                    "--operation",
                    "auto",
                    "--profile",
                    prof,
                    "--tools-dir",
                    str(self.tools_dir),
                ]
                rc_pf, out_pf = self._run_subprocess_streaming(build_worker_command("--run-kit", self.active_kit_root, pf_args))
                if rc_pf != 0:
                    raise RuntimeError(f"环境预检未通过（exit={rc_pf}）：\n{out_pf[-1200:]}")
                self.log("[OK] 全部环境体检通过！请切换到「② 方案与密码设置」或直接开始备份刷机。", "OK")
                self.root.after(0, lambda: messagebox.showinfo("环境准备完成", f"环境已 100% 就绪！（脚本版本：{self.active_kit_version}）\n接下来请确认方案和密码，即可开始备份与刷机。"))

            self._launch_bg_task("正在拉取 GitHub 最新版并完成环境体检...", task)

        def _action_install_drivers(self) -> None:
            def task() -> None:
                if not (self.tools_dir / "host-tools-win64" / "qmk_driver_installer" / "qmk_driver_installer.exe").is_file():
                    self.log("[INFO] 尚未下载 Windows 工具包，先自动拉取 host_tools_win64...", "INFO")
                    rc, out = self._run_subprocess_streaming(
                        build_worker_command(
                            "--run-kit",
                            self.active_kit_root,
                            [
                                "fetch-assets",
                                "--host-platform",
                                "win64",
                                "--profile",
                                "none",
                                "--cache-dir",
                                str(self.cache_dir),
                                "--tools-dir",
                                str(self.tools_dir),
                            ],
                        )
                    )
                    if rc != 0:
                        raise RuntimeError(f"下载驱动工具包失败：\n{out[-1000:]}")
                res = install_unisoc_winusb_drivers(self.tools_dir, log_cb=self.log)
                if not res.get("ok"):
                    raise RuntimeError(res.get("error") or f"驱动安装失败：\n{res.get('output', '')}")
                self.log("[OK] 展锐 BROM (1782:4D00) 与 Boot Diag (1782:4D03) 驱动安装成功！", "OK")
                self.root.after(0, lambda: messagebox.showinfo("驱动安装成功", "展锐 WinUSB 驱动（1782:4D00 与 1782:4D03）已成功预装进 Windows！"))

            self._launch_bg_task("正在安装展锐 WinUSB 驱动 (--force --all)...", task)

        def _action_generate_adb_key(self) -> None:
            def task() -> None:
                res = ensure_adb_pubkey(self.tools_dir)
                if not res.get("ok"):
                    raise RuntimeError(str(res.get("error")))
                self.log(f"[OK] 已就绪 ADB 公钥：{res['path']}", "OK")

            self._launch_bg_task("正在生成 ADB RSA 密钥...", task)

        def _action_test_webui_pw(self) -> None:
            pw = self.webui_pw_var.get()
            self.webui_pw_status.configure(text="验证中...", fg=PALETTE["info_fg"])

            def worker() -> None:
                res = test_webui_password(pw)
                def finish() -> None:
                    if res.get("ok"):
                        self.webui_pw_status.configure(text="✓ 密码验证通过", fg=PALETTE["ok_fg"])
                        self.log(f"[OK] {res['message']}", "OK")
                    else:
                        self.webui_pw_status.configure(text="✗ 验证失败", fg=PALETTE["err_fg"])
                        self.log(f"[ERR] {res['message']}", "ERR")
                        messagebox.showwarning("原厂后台密码校验未通过", res["message"])
                if not self._closing:
                    self.root.after(0, finish)

            threading.Thread(target=worker, daemon=True).start()

        def _validate_common_form(self, *, require_wifi: bool = False) -> bool:
            if any(i.get("code") == "WRONG_DEVICE_MODEL" for i in (self.last_usb_state.get("issues") or [])):
                messagebox.showerror("危险拦截", "检测到非 F50 Pro (MU3356) 机型，已禁止操作！")
                return False
            if require_wifi and self.profile_var.get() in ("2-dual-stock-openwrt", "3-dual-full"):
                wpw = self.wifi_pw_var.get().strip()
                if wpw and len(wpw) < 8:
                    messagebox.showwarning("Wi-Fi 密码过短", "OpenWrt Wi-Fi 密码至少需要 8 位字符（或留空使用底包初始密码）。")
                    self.nb.select(self.tab_cfg)
                    return False
            if not self.gen_root_pw_var.get() and not self.custom_root_pw_var.get().strip():
                messagebox.showwarning("缺少 root 密码", "请勾选「自动生成高强度随机密码」，或填写自定义 OpenWrt 管理员密码。")
                self.nb.select(self.tab_cfg)
                return False
            return True

        def _action_backup_only(self) -> None:
            if not self._validate_common_form():
                return
            session_dir = Path(self.session_dir_var.get())
            backup_dir = session_dir / "backup"
            pw = self.webui_pw_var.get().strip()
            if not pw:
                if not messagebox.askyesno(
                    "未填原厂后台密码",
                    "未填写原厂后台密码时，脚本无法自动触发重启进下载口（需出现 Waiting for boot_diag 时手动重启/进下载口）。\n是否继续？",
                ):
                    self.nb.select(self.tab_cfg)
                    return

            def task() -> None:
                args = [
                    "backup",
                    "--output-dir",
                    str(backup_dir),
                    "--tools-dir",
                    str(self.tools_dir),
                    "--authorize-device-reboot",
                ]
                if pw:
                    args += ["--webui-password", pw]
                self.log("开始只读全量备份原厂闪存（约 2~5 分钟，期间设备会自动重启进下载模式，请勿拔线）...", "INFO")
                rc, out = self._run_subprocess_streaming(build_worker_command("--run-kit", self.active_kit_root, args))
                if rc != 0:
                    raise RuntimeError(f"原厂分区备份失败（exit={rc}）：\n{out[-1500:]}")
                self.log(f"[OK] 原厂全量备份成功并校验通过：{backup_dir}（建议另存一份副本保底）", "OK")
                self.root.after(0, lambda: messagebox.showinfo("原厂备份成功", f"原厂分区已完整备份并校验通过！\n路径：{backup_dir}\n建议复制一份到其他硬盘或网盘留底。"))

            self._launch_bg_task("正在全量只读备份原厂分区（切勿拔线）...", task)

        def _action_dry_run_plan(self) -> None:
            if not self._validate_common_form():
                return
            session_dir = Path(self.session_dir_var.get())
            prof = self.profile_var.get()

            def task() -> None:
                args = [
                    "plan",
                    "--profile",
                    prof,
                    "--work-dir",
                    str(session_dir),
                    "--tools-dir",
                    str(self.tools_dir),
                    "--cache-dir",
                    str(self.cache_dir),
                ]
                if self.openclash_var.get() and prof in ("2-dual-stock-openwrt", "3-dual-full"):
                    args.append("--openclash")
                self.log("正在执行 100% 离线干跑预览（不接触设备）...", "INFO")
                rc, out = self._run_subprocess_streaming(build_worker_command("--run-kit", self.active_kit_root, args))
                if rc != 0:
                    raise RuntimeError(f"干跑预览失败（exit={rc}）：\n{out[-1500:]}")
                parsed = _extract_last_json_object(out) or {}
                st = parsed.get("status")
                if st == "BACKUP_REQUIRED":
                    self.root.after(0, lambda: messagebox.showinfo("需先备份原厂分区", "当前工作目录尚无原厂备份。\n请先点击「① 只读备份原厂分区」，或直接点击「③ 开始一键刷入」在单次会话中自动先备份再刷入。"))
                    return
                if st == "OFFLINE_ASSETS_REQUIRED":
                    raise RuntimeError("缺少所需离线资源包，请先在「① 环境体检」中点击「一键拉取 GitHub 最新版」。")
                write_mb = round(int((parsed.get("build") or {}).get("total_brom_write_bytes") or 0) / (1024 * 1024), 2)
                summary = (
                    f"状态：{st}\n"
                    f"目标方案：{prof}\n"
                    f"预计写入大小：{write_mb} MiB\n"
                    f"受保护分区写入数：0 (FORBIDDEN_PARTITIONS 严格锁定)\n"
                    f"设备已被修改：{parsed.get('device_mutated', False)}\n\n"
                    f"确认无误后，即可点击「③ 开始一键刷入」。"
                )
                self.log(f"[OK] 离线干跑预览通过（预计写入 {write_mb} MiB）。", "OK")
                self.root.after(0, lambda: messagebox.showinfo("离线干跑预览通过", summary))

            self._launch_bg_task("正在生成离线干跑预览...", task)

        def _action_execute_auto(self) -> None:
            if not self._validate_common_form(require_wifi=True):
                return
            session_dir = Path(self.session_dir_var.get())
            backup_xml = session_dir / "backup" / "partition_list.xml"
            has_backup = backup_xml.is_file()
            prof = self.profile_var.get()
            pw = self.webui_pw_var.get().strip()

            reuse_backup = False
            if has_backup:
                ans = messagebox.askyesnocancel(
                    "检测到已有原厂备份",
                    f"在 {session_dir / 'backup'} 中检测到已有备份。\n\n"
                    "• 点击「是」：复用该备份直接构建并刷入（更快，会校验设备指纹防止刷错机）\n"
                    "• 点击「否」：重新在单次会话中现场备份并刷入\n"
                    "• 点击「取消」：暂不执行",
                )
                if ans is None:
                    return
                reuse_backup = bool(ans)

            confirm_msg = (
                f"即将开始正式刷机，请再次确认：\n\n"
                f"• 刷机方案：{prof}\n"
                f"• 安装离线 OpenClash：{'是' if (self.openclash_var.get() and prof != '1-android-ufi') else '否'}\n"
                f"• 备份策略：{'复用已有本机备份' if reuse_backup else '单次会话自动先备份后刷入（零中途插拔）'}\n"
                f"• 工作目录：{session_dir}\n\n"
                f"⚠️ 刷机约需 5~10 分钟，期间绝对不要拔掉 USB 线或断电！\n确认开始执行吗？"
            )
            if not messagebox.askyesno("正式刷机最终安全确认", confirm_msg, icon="warning"):
                return

            def task() -> None:
                args = [
                    "auto",
                    "--profile",
                    prof,
                    "--work-dir",
                    str(session_dir),
                    "--tools-dir",
                    str(self.tools_dir),
                    "--cache-dir",
                    str(self.cache_dir),
                    "--execute",
                ]
                if reuse_backup:
                    args.append("--reuse-backup")
                if pw:
                    args += ["--webui-password", pw]
                if prof in ("2-dual-stock-openwrt", "3-dual-full"):
                    ssid = self.wifi_ssid_var.get().strip() or "F50Pro-OpenWrt"
                    args += ["--wifi-ssid", ssid]
                    wpw = self.wifi_pw_var.get().strip()
                    if wpw:
                        args += ["--wifi-password", wpw]
                    if self.gen_root_pw_var.get():
                        args.append("--generate-password")
                    else:
                        args += ["--root-password", self.custom_root_pw_var.get().strip()]
                    if self.openclash_var.get():
                        args.append("--openclash")

                self.log("正式启动一键刷入与自动配网流程，请耐心等待，切勿拔线...", "INFO")
                rc, out = self._run_subprocess_streaming(build_worker_command("--run-kit", self.active_kit_root, args))
                if rc != 0:
                    fail_rep = None
                    fr_path = session_dir / "build" / "flash-run" / "flash_failure_report.json"
                    if fr_path.is_file():
                        try:
                            fail_rep = json.loads(fr_path.read_text(encoding="utf-8"))
                        except Exception:
                            pass
                    diag = diagnose_failure(out, failure_report=fail_rep)
                    self.root.after(0, lambda: self._show_diag_banner(diag))
                    raise RuntimeError(f"刷机流程中断（exit={rc}）：{diag['title']}")

                self.log("[OK] 恭喜！一键刷机、自动配网与端到端验收全部通过！", "OK")
                self.root.after(0, self._show_success_credentials_popup)

            self._launch_bg_task("正在一键刷入与自动配网（约 5~10 分钟，切勿拔线）...", task, is_flash=True)

        def _show_success_credentials_popup(self) -> None:
            session_dir = Path(self.session_dir_var.get())
            ow_cred = session_dir / "build" / "openwrt-credentials.json"
            and_cred = session_dir / "build" / "android-ttyd-credentials.json"
            lines = ["刷机与自动配网已全部完成！"]
            if ow_cred.is_file():
                try:
                    data = json.loads(ow_cred.read_text(encoding="utf-8"))
                    lines.append(f"\n• OpenWrt 管理地址：http://192.168.77.1\n• 用户名：root\n• 管理员密码：{data.get('password', '(见文件)')}")
                except Exception:
                    lines.append(f"\n• OpenWrt 密码文件：{ow_cred}")
            if and_cred.is_file():
                lines.append(f"\n• 安卓网页终端口令文件：{and_cred}")
            lines.append("\n• 切换系统：长按机身实体按键 5 秒以上松手即可双向切换。")
            messagebox.showinfo("刷机全部完成", "\n".join(lines))

        def _action_show_credentials(self) -> None:
            session_dir = Path(self.session_dir_var.get())
            ow_cred = session_dir / "build" / "openwrt-credentials.json"
            and_cred = session_dir / "build" / "android-ttyd-credentials.json"
            msgs: list[str] = []
            if ow_cred.is_file():
                msgs.append(f"[OpenWrt 密码文件]\n{ow_cred}\n{ow_cred.read_text(encoding='utf-8')}")
            if and_cred.is_file():
                msgs.append(f"[安卓 ttyd 密码文件]\n{and_cred}\n{and_cred.read_text(encoding='utf-8')}")
            if not msgs:
                messagebox.showinfo("暂无密码文件", f"在 {session_dir / 'build'} 下尚未找到生成的密码文件（需完成刷机配网后生成）。")
                return
            messagebox.showinfo("本机保存的设备登录凭据", "\n\n".join(msgs))

        def _action_probe(self) -> None:
            session_dir = Path(self.session_dir_var.get())
            prof = self.profile_var.get()
            cred_file = session_dir / "build" / "openwrt-credentials.json"

            def task() -> None:
                args = ["probe", "--profile", prof, "--tools-dir", str(self.tools_dir)]
                if cred_file.is_file():
                    args += ["--credentials-file", str(cred_file)]
                if self.openclash_var.get() and prof != "1-android-ufi":
                    args.append("--openclash")
                rc, out = self._run_subprocess_streaming(build_worker_command("--run-kit", self.active_kit_root, args))
                if rc != 0:
                    raise RuntimeError(f"只读巡检存在异常项（exit={rc}），请查看上方 JSON 细节。")
                self.log("[OK] 只读巡检 PASS：双系统状态与宿主机防断网隔离全部健康！", "OK")

            self._launch_bg_task("正在执行刷后只读体检 (probe)...", task)

        def _action_repair_usb_net(self) -> None:
            def task() -> None:
                self.log("正在扫描 USB 设备并绑定微软 RNDIS6 + 执行防断网隔离...", "INFO")
                res = try_repair_usb_network(self.active_kit_root)
                self.log(json.dumps(res, indent=2, ensure_ascii=False))
                if not res.get("ok"):
                    raise RuntimeError(str(res.get("error") or "USB 网卡修复失败"))
                self.log("[OK] USB 网卡扫描与隔离完成。", "OK")
                self.root.after(0, self._trigger_radar_now)

            self._launch_bg_task("正在扫描并修复 USB 网卡...", task)

        def _action_host_net(self, sub_args: list[str]) -> None:
            def task() -> None:
                rc, out = self._run_subprocess_streaming(
                    build_worker_command("--run-host-network", self.active_kit_root, sub_args)
                )
                if rc != 0:
                    raise RuntimeError(f"网卡配置失败（exit={rc}）：\n{out[-800:]}")
                self.log("[OK] 宿主机 USB 网卡模式已更新。", "OK")

            self._launch_bg_task("正在更新宿主机 USB 网卡配置...", task)

        def _action_restore_host_net(self) -> None:
            session_dir = Path(self.session_dir_var.get())
            snap = session_dir / "build" / "host_network_snapshot.json"
            if not snap.is_file():
                messagebox.showinfo("未找到快照", f"未找到网卡隔离快照：{snap}")
                return
            self._action_host_net(["restore", "--snapshot", str(snap)])

        def _action_rollback_a(self) -> None:
            session_dir = Path(self.session_dir_var.get())
            rb = session_dir / "build" / "stage3" / "misc_rollback_a.bin"
            spd = self.tools_dir / "host-tools-win64" / "spd_dump_251" / "spd_dump.exe"
            if not rb.is_file():
                messagebox.showwarning("缺少回退引导块", f"未找到 {rb}（需先对本机执行过构建/干跑预览）。")
                return
            if not spd.is_file():
                messagebox.showwarning("缺少 spd_dump.exe", "请先在「① 环境体检」中拉取 Windows 工具包。")
                return
            if not messagebox.askyesno(
                "确认应急切回原厂安卓 (_a)",
                "此操作将等待设备进入展锐下载口 (1782:4D00)，仅把本机原始引导块写回 misc 偏移 2048 处并重启回原厂安卓 _a 槽。\n确认执行吗？",
            ):
                return

            def task() -> None:
                cmd = [str(spd), "--wait", "120", "--kickto", "2", "wof", "misc", "2048", str(rb), "reset"]
                rc, out = self._run_subprocess_streaming(cmd)
                if rc != 0:
                    raise RuntimeError(f"应急回退失败（exit={rc}）：\n{out[-1200:]}")
                self.log("[OK] 已写回原始 _a 槽引导块并重启设备回原厂安卓！", "OK")

            self._launch_bg_task("等待下载口并切回原厂安卓 (_a)...", task)

        def _action_export_diag(self) -> None:
            default_name = f"f50pro-diagnostic-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
            out_path = filedialog.asksaveasfilename(
                initialdir=str(self.workspace_dir),
                initialfile=default_name,
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt")],
                title="保存脱敏诊断报告",
            )
            if not out_path:
                return
            report = build_sanitized_diagnostic_report(
                kit_version=self.active_kit_version,
                workspace_dir=Path(self.session_dir_var.get()),
                log_tail="\n".join(self.full_log_lines[-200:]),
                secrets=self._active_secrets(),
            )
            Path(out_path).write_text(report, encoding="utf-8")
            self.log(f"[OK] 已导出脱敏诊断报告（已自动隐藏密码与隐私信息）：{out_path}", "OK")
            messagebox.showinfo("导出成功", f"脱敏诊断报告已保存：\n{out_path}\n可直接发给群友或开发者排查问题。")

        def _on_close(self) -> None:
            if self.busy:
                if not messagebox.askyesno("任务仍在运行", "当前有任务正在执行，关闭窗口会中断它。确定退出吗？"):
                    return
                if self.active_proc:
                    try:
                        self.active_proc.terminate()
                    except Exception:
                        pass
            self._closing = True
            self.root.destroy()

    root = tk.Tk()
    if smoke_test:
        root.withdraw()
    app = F50ProFlasherApp(root, smoke_test=smoke_test)
    if smoke_test:
        for tab in (app.tab_env, app.tab_cfg, app.tab_run, app.tab_tools):
            app.nb.select(tab)
            root.update_idletasks()
        app._show_diag_banner(diagnose_failure("No matching device found"))
        root.update_idletasks()
        app._hide_diag_banner()
        root.update()
        app._closing = True
        root.destroy()
        print("GUI_SMOKE_OK")
        return 0
    root.mainloop()
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in ("--run-kit", "--run-host-network"):
        return _dispatch_embedded_script(args[0], args)
    if args and args[0] == "--smoke-gui":
        return launch_gui(smoke_test=True)
    return launch_gui(smoke_test=False)


if __name__ == "__main__":
    raise SystemExit(main())
