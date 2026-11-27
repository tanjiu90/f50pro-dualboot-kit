"""Beginner-friendly Windows GUI wizard + trust-gated isolated `--run-kit` worker for F50 Pro Dual-Boot Kit."""
from __future__ import annotations

import ctypes
import datetime
import io
import json
import os
import queue
import runpy
import secrets as _secrets
import string
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
    check_native_tool_path_compat,
    detect_usb_device_state,
    diagnose_failure,
    ensure_adb_pubkey,
    extract_last_json_object,
    inspect_unisoc_drivers,
    install_unisoc_winusb_drivers,
    is_windows_admin,
    repair_usb_network_via_worker,
    sanitize_diagnostic_text,
    test_webui_password,
)
from gui.github_updater import (  # noqa: E402
    PRESET_MIRRORS,
    download_and_verify_kit_release,
    fetch_latest_release_info,
    normalize_mirror_prefix,
    resolve_kit_version,
    verify_cached_kit_tree,
    verify_kit_compatibility,
)


def default_workspace_dir() -> Path:
    """User-facing workspace for backups & logs (beside exe when frozen, or %LOCALAPPDATA% outside Git repo in source mode)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "workspace"
    local_app = os.environ.get("LOCALAPPDATA")
    if local_app:
        return Path(local_app) / "F50Pro-Flasher"
    return Path.home() / ".f50pro-flasher"


def _harden_admin_dir_acl(path: Path) -> bool:
    """Reset any prior explicit grants and restrict elevated ProgramData runtime directory strictly to SYSTEM & Administrators."""
    if sys.platform != "win32" or not is_windows_admin():
        return True
    try:
        path.mkdir(parents=True, exist_ok=True)
        r_reset = subprocess.run(
            ["icacls", str(path), "/reset", "/T", "/C"],
            capture_output=True,
            text=True,
            timeout=10.0,
            **_no_window_kwargs(),
        )
        if r_reset.returncode != 0:
            return False
        res = subprocess.run(
            [
                "icacls",
                str(path),
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
            ],
            capture_output=True,
            text=True,
            timeout=10.0,
            **_no_window_kwargs(),
        )
        return res.returncode == 0
    except Exception:
        return False


def default_trusted_runtime_dir() -> Path:
    """Protected directory for elevated executable tools & verified updated kits (fail-closed ACL check on Windows)."""
    if getattr(sys, "frozen", False) and sys.platform == "win32" and is_windows_admin():
        prog_data = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
        root = Path(prog_data) / "F50Pro-Flasher"
        if not _harden_admin_dir_acl(root):
            raise RuntimeError(f"Failed hardening Administrator-only ACL on protected runtime directory: {root}")
        return root
    return default_workspace_dir()


def default_trusted_kit_store_dir() -> Path:
    return default_trusted_runtime_dir() / "trusted-kits"


def default_trusted_tools_dir() -> Path:
    return default_trusted_runtime_dir() / "runtime-tools"


def bundled_kit_root() -> Path:
    """Return immutable bundled offline fallback kit root (containing scripts/kit.py and assets/)."""
    cand = _BUNDLE_ROOT
    if (cand / "scripts" / "kit.py").is_file():
        return cand
    alt = _THIS_FILE.parents[1]
    if (alt / "scripts" / "kit.py").is_file():
        return alt
    return cand


def _ensure_worker_streams() -> None:
    """Guarantee usable UTF-8 stdin/stdout/stderr even when launched from a PyInstaller `--windowed` executable."""
    if sys.stdin is not None and hasattr(sys.stdin, "reconfigure"):
        try:
            sys.stdin.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if sys.stdout is None:
        sys.stdout = io.TextIOWrapper(open(os.devnull, "wb"), encoding="utf-8", errors="replace")
    elif hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        except Exception:
            pass
    if sys.stderr is None:
        sys.stderr = io.TextIOWrapper(open(os.devnull, "wb"), encoding="utf-8", errors="replace")
    elif hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        except Exception:
            pass


def _is_allowed_worker_kit_root(kit_root: Path) -> bool:
    """Allow worker execution ONLY from immutable bundled_kit_root OR a verified kit inside trusted-kits."""
    resolved = kit_root.resolve()
    if resolved == bundled_kit_root().resolve():
        return True
    trusted_store = default_trusted_kit_store_dir().resolve()
    try:
        resolved.relative_to(trusted_store)
    except ValueError:
        return False
    for cand_tag_dir in (resolved, resolved.parent):
        if cand_tag_dir.parent == trusted_store:
            verified = verify_cached_kit_tree(cand_tag_dir)
            if verified is not None and Path(verified["kit_root"]).resolve() == resolved:
                try:
                    verify_kit_compatibility(resolved)
                    return True
                except Exception:
                    return False
    return False


def _emit_worker_error(err_type: str, message: str) -> None:
    safe_msg = sanitize_diagnostic_text(message)
    envelope = json.dumps({"worker_error": True, "error_type": err_type, "message": safe_msg}, ensure_ascii=False)
    print(f"[ERR] {err_type}: {safe_msg}", file=sys.stderr, flush=True)
    print(envelope, file=sys.stderr, flush=True)


def _dispatch_embedded_script(mode_flag: str, argv: list[str]) -> int:
    """Execute kit.py or host_network.py ONLY from a trust-verified kit root; NEVER escape uncaught exceptions to runw.exe."""
    _ensure_worker_streams()
    if len(argv) < 2:
        _emit_worker_error("UsageError", f"Usage: {mode_flag} <kit_root> [script args...]")
        return 2
    kit_root = Path(argv[1]).resolve()
    if not _is_allowed_worker_kit_root(kit_root):
        _emit_worker_error("UntrustedKitRoot", "Refusing to execute elevated worker from untrusted or unverified kit root.")
        return 2
    script_name = "kit.py" if mode_flag == "--run-kit" else "host_network.py"
    script_path = kit_root / "scripts" / script_name
    if not script_path.is_file():
        _emit_worker_error("FileNotFoundError", f"Script not found: {script_name}")
        return 2

    scripts_dir = str(kit_root / "scripts")
    sys.path.insert(0, scripts_dir)
    os.chdir(str(kit_root))
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
        _emit_worker_error("SystemExit", str(code))
        return 1
    except BaseException as exc:
        _emit_worker_error(type(exc).__name__, str(exc))
        return 1
    finally:
        for stream in (sys.stdout, sys.stderr):
            if stream is not None:
                try:
                    stream.flush()
                except Exception:
                    pass


def build_worker_command(mode_flag: str, kit_root: Path, script_args: list[str]) -> list[str]:
    """Build subprocess argv invoking this app's embedded Python runtime in isolated worker mode."""
    if getattr(sys, "frozen", False):
        return [sys.executable, mode_flag, str(kit_root), *script_args]
    return [sys.executable, str(_THIS_FILE), mode_flag, str(kit_root), *script_args]


def _no_window_kwargs() -> dict[str, Any]:
    if sys.platform == "win32":
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)}
    return {}


def _generate_strong_wifi_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(_secrets.choice(alphabet) for _ in range(length))


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


class _DiagnosedTaskError(RuntimeError):
    """Error carrying an already-classified diagnosis so outer catch never overwrites it."""

    def __init__(self, message: str, diag: dict[str, Any]) -> None:
        super().__init__(message)
        self.diag = diag


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
            "安卓 _a 槽 100% 保持原厂不动；OpenWrt 25.12.5 装在 _b 槽（长按按键 5 秒切回原厂安卓）",
        ),
        (
            "1-android-ufi",
            "方案 1：仅安卓 Root + UFI-TOOLS",
            "只给原厂安卓 _a 槽刷入 Magisk 28103 与 UFI-TOOLS 高级管理后台（:2333 / 网页终端 :1146），不装 OpenWrt",
        ),
    ]

    class ScrollableTab(ttk.Frame):
        """Scrollable container ensuring controls never clip at 125%/150%/200% DPI or 1366x768 screens."""

        def __init__(self, parent: tk.Widget) -> None:
            super().__init__(parent)
            self.canvas = tk.Canvas(self, bg=PALETTE["bg"], highlightthickness=0, borderwidth=0)
            self.vbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
            self.body = tk.Frame(self.canvas, bg=PALETTE["bg"], padx=10, pady=10)
            self._win_id = self.canvas.create_window((0, 0), window=self.body, anchor="nw")
            self.canvas.configure(yscrollcommand=self.vbar.set)
            self.canvas.pack(side="left", fill="both", expand=True)
            self.vbar.pack(side="right", fill="y")
            self.body.bind("<Configure>", lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
            self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self._win_id, width=e.width))

    class F50ProFlasherApp:
        def __init__(self, root: tk.Tk, *, smoke_test: bool = False) -> None:
            self.root = root
            self._smoke_test = smoke_test
            self.root.title("中兴 F50 Pro (MU3356) 一键双系统刷机助手")
            self.root.geometry("980x760")
            self.root.minsize(760, 560)
            self.root.configure(bg=PALETTE["bg"])

            self.workspace_dir = default_workspace_dir()
            self.kit_store_dir = default_trusted_kit_store_dir()
            self.tools_dir = default_trusted_tools_dir()
            self.cache_dir = self.workspace_dir / "bundle-cache"
            self.workspace_dir.mkdir(parents=True, exist_ok=True)
            self.cache_dir.mkdir(parents=True, exist_ok=True)

            # Security rule (P0-1): startup ALWAYS anchors to immutable bundled kit (never trusts writable caches unverified).
            self.active_kit_root: Path = bundled_kit_root()
            self.bundled_kit_version: str = resolve_kit_version(self.active_kit_root)
            self.active_kit_version: str = self.bundled_kit_version

            # Single thread-safe UI event queue: workers NEVER touch Tk widgets or Tk vars directly!
            self.ui_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
            self.full_log_lines: list[str] = []
            self.busy = False
            self.active_proc: subprocess.Popen[str] | None = None
            self.active_is_flash = False
            self.last_diag: dict[str, Any] | None = None
            self.last_usb_state: dict[str, Any] = {"state": "unknown", "query_ok": True, "present_modes": [], "label": "正在检测 USB 设备...", "issues": []}
            self._radar_running = False
            self._closing = False
            self._approved_plan: dict[str, Any] | None = None
            self._dynamic_wrap_labels: list[tuple[tk.Label, int]] = []

            # Form variables (read/written ONLY on the main Tk thread)
            self.mirror_choice_var = tk.StringVar(value=PRESET_MIRRORS[0][0])
            self.custom_mirror_var = tk.StringVar(value="")
            self.profile_var = tk.StringVar(value="3-dual-full")
            self.openclash_var = tk.BooleanVar(value=True)
            self.webui_pw_var = tk.StringVar(value="")
            self.wifi_ssid_var = tk.StringVar(value="F50Pro-OpenWrt")
            self.auto_wifi_pw_var = tk.BooleanVar(value=True)
            self.wifi_pw_var = tk.StringVar(value="")
            self.gen_root_pw_var = tk.BooleanVar(value=True)
            self.custom_root_pw_var = tk.StringVar(value="")
            self.session_dir_var = tk.StringVar(value=str(self.workspace_dir / "my-f50pro"))
            self.session_dir_var.trace_add("write", lambda *_: self._invalidate_approved_plan())
            self.status_step_var = tk.StringVar(value="就绪：请先点击「一键拉取并完成全部体检」")

            self._setup_styles()
            self._build_ui()
            if not self._smoke_test:
                self._drain_ui_queue()
                self._refresh_env_cards_async()
                self._schedule_usb_radar()
            self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        def _snapshot_config(self) -> dict[str, Any]:
            """Freeze all Tk form values into an immutable plain dict on the main thread before spawning a worker."""
            label = self.mirror_choice_var.get()
            preset_val = ""
            for name, val in PRESET_MIRRORS:
                if name == label:
                    preset_val = val
                    break
            offline = preset_val == "__OFFLINE__"
            if offline:
                mirror_prefix = "__OFFLINE__"
            else:
                custom = self.custom_mirror_var.get().strip()
                mirror_prefix = normalize_mirror_prefix(custom) if custom else preset_val

            webui_pw = self.webui_pw_var.get()  # Preserve exact password characters (no .strip())
            wifi_pw = self.wifi_pw_var.get()
            custom_root_pw = self.custom_root_pw_var.get()
            wifi_ssid = self.wifi_ssid_var.get().strip() or "F50Pro-OpenWrt"
            secrets = [s for s in (webui_pw, wifi_pw, custom_root_pw) if s]
            return {
                "mirror_prefix": mirror_prefix,
                "offline": offline,
                "profile": self.profile_var.get(),
                "openclash": bool(self.openclash_var.get()),
                "webui_pw": webui_pw,
                "wifi_ssid": wifi_ssid,
                "auto_wifi_pw": bool(self.auto_wifi_pw_var.get()),
                "wifi_pw": wifi_pw,
                "gen_root_pw": bool(self.gen_root_pw_var.get()),
                "custom_root_pw": custom_root_pw,
                "session_dir": Path(self.session_dir_var.get()),
                "kit_root": self.active_kit_root,
                "kit_version": self.active_kit_version,
                "bundled_kit_version": self.bundled_kit_version,
                "tools_dir": self.tools_dir,
                "cache_dir": self.cache_dir,
                "secrets": secrets,
            }

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
            style.configure("TNotebook.Tab", padding=(12, 6), font=("Microsoft YaHei UI", 10, "bold"))
            style.configure("Primary.TButton", font=("Microsoft YaHei UI", 10, "bold"), padding=(14, 7))
            style.configure("Action.TButton", font=("Microsoft YaHei UI", 9, "bold"), padding=(10, 5))
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
            hdr = tk.Frame(self.root, bg=PALETTE["header"], padx=16, pady=10)
            hdr.pack(fill="x")

            left_h = tk.Frame(hdr, bg=PALETTE["header"])
            left_h.pack(side="left", fill="x", expand=True)
            tk.Label(
                left_h,
                text="中兴 F50 Pro (MU3356) 一键双系统刷机助手",
                bg=PALETTE["header"],
                fg=PALETTE["header_fg"],
                font=("Microsoft YaHei UI", 13, "bold"),
            ).pack(anchor="w")
            tk.Label(
                left_h,
                text="仅支持中兴 F50 Pro 插卡版(B28) / 双eSIM版(B15) · 纯净公开 OpenWrt 25.12.5 · 官方摘要校验与自动排障",
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
            radar_wrap.pack(fill="x", padx=12, pady=(8, 4))
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
                justify="left",
                wraplength=680,
            )
            self.radar_hint_lbl.pack(fill="x", pady=(2, 0))
            self._dynamic_wrap_labels.append((self.radar_hint_lbl, 260))

            radar_btns = tk.Frame(radar_wrap, bg=PALETTE["info_bg"])
            radar_btns.pack(side="right", padx=(8, 0))
            self.radar_btns = radar_btns
            ttk.Button(radar_btns, text="刷新设备", style="Action.TButton", command=self._trigger_radar_now).pack(side="left", padx=(0, 6))
            ttk.Button(radar_btns, text="一键修驱动", style="Action.TButton", command=self._action_install_drivers).pack(side="left")

            # --- Main Notebook (4 Scrollable Guided Tabs) ---
            self.nb = ttk.Notebook(self.root)
            self.nb.pack(fill="both", expand=True, padx=12, pady=4)

            self.tab_env = ScrollableTab(self.nb)
            self.tab_cfg = ScrollableTab(self.nb)
            self.tab_run = ScrollableTab(self.nb)
            self.tab_tools = ScrollableTab(self.nb)

            self.nb.add(self.tab_env, text=" ① 环境体检与自动拉取 ")
            self.nb.add(self.tab_cfg, text=" ② 方案与密码设置 ")
            self.nb.add(self.tab_run, text=" ③ 备份、预览与一键刷机 ")
            self.nb.add(self.tab_tools, text=" ④ 刷后体检与受控回退 ")

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
                self.diag_frame, text="", bg=PALETTE["err_bg"], fg=PALETTE["text"], font=("Microsoft YaHei UI", 9), justify="left", anchor="w", wraplength=760
            )
            self.diag_body_lbl.pack(fill="x", pady=(2, 6))
            self._dynamic_wrap_labels.append((self.diag_body_lbl, 60))
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
            ttk.Button(prog_row, text="导出脱敏报告", command=self._action_export_diag).pack(side="right", padx=(6, 0))
            ttk.Button(prog_row, text="清空日志", command=self._clear_log).pack(side="right")

            self.progress = ttk.Progressbar(bottom, mode="indeterminate")
            self.progress.pack(fill="x", pady=(0, 6))

            self.log_box = scrolledtext.ScrolledText(
                bottom,
                height=8,
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

            self.root.bind("<Configure>", self._on_root_resize)

        def _on_root_resize(self, event: Any) -> None:
            if event.widget is self.root and event.width > 400:
                for lbl, margin in self._dynamic_wrap_labels:
                    try:
                        lbl.configure(wraplength=max(320, event.width - margin))
                    except Exception:
                        pass

        def _on_mirror_choice_changed(self, _event: Any = None) -> None:
            is_off = False
            for name, val in PRESET_MIRRORS:
                if name == self.mirror_choice_var.get():
                    is_off = val == "__OFFLINE__"
                    break
            self.custom_mirror_entry.configure(state="disabled" if is_off else "normal")

        def _build_tab_env(self) -> None:
            pad = self.tab_env.body

            c1 = self._make_card(pad)
            c1.pack(fill="x", pady=(0, 10))
            ttk.Label(c1.inner, text="1. GitHub 拉取源（摘要直连官方 GitHub 校验并检查协议兼容与 25.12.5 公共策略）", style="Title.TLabel").pack(anchor="w")

            row1 = tk.Frame(c1.inner, bg=PALETTE["card"])
            row1.pack(fill="x", pady=(8, 4))
            ttk.Label(row1, text="下载线路：", style="Card.TLabel").pack(side="left")
            cb = ttk.Combobox(
                row1,
                textvariable=self.mirror_choice_var,
                values=[m[0] for m in PRESET_MIRRORS],
                state="readonly",
                width=34,
            )
            cb.pack(side="left", padx=(4, 12))
            cb.bind("<<ComboboxSelected>>", self._on_mirror_choice_changed)
            ttk.Label(row1, text="自定义 HTTPS 镜像（离线模式自动禁用）：", style="Card.TLabel").pack(side="left")
            self.custom_mirror_entry = ttk.Entry(row1, textvariable=self.custom_mirror_var, width=22)
            self.custom_mirror_entry.pack(side="left", fill="x", expand=True, padx=(4, 0))

            row1b = tk.Frame(c1.inner, bg=PALETTE["card"])
            row1b.pack(fill="x", pady=(4, 0))
            ttk.Label(
                row1b,
                text=f"离线包缓存目录：{self.cache_dir}",
                style="Muted.TLabel",
            ).pack(side="left")
            ttk.Button(row1b, text="打开缓存目录", command=lambda: self._open_folder(self.cache_dir)).pack(side="right")

            c2 = self._make_card(pad)
            c2.pack(fill="x", pady=(0, 10))
            ttk.Label(c2.inner, text="2. 电脑环境自动体检（工具与驱动安装前逐字节校验官方压缩包哈希）", style="Title.TLabel").pack(anchor="w", pady=(0, 6))

            self.env_labels: dict[str, tk.Label] = {}
            checks = [
                ("admin", "管理员权限"),
                ("path", "目录路径字符兼容性"),
                ("disk", "磁盘剩余空间 (需 >= 15 GB)"),
                ("kit", "刷机脚本与受保护工具包"),
                ("driver", "展锐 WinUSB 驱动 (1782:4D00 & 4D03)"),
                ("adbkey", "本机 ADB RSA 密钥 (adbkey.pub)"),
            ]
            for key, name in checks:
                r = tk.Frame(c2.inner, bg=PALETTE["card"])
                r.pack(fill="x", pady=3)
                tk.Label(r, text=f"• {name}：", bg=PALETTE["card"], fg=PALETTE["text"], width=32, anchor="w", font=("Microsoft YaHei UI", 9, "bold")).pack(side="left")
                lbl = tk.Label(r, text="检测中...", bg=PALETTE["card"], fg=PALETTE["muted"], anchor="w", font=("Microsoft YaHei UI", 9))
                lbl.pack(side="left", fill="x", expand=True)
                self.env_labels[key] = lbl

            act = tk.Frame(pad, bg=PALETTE["bg"])
            act.pack(fill="x", pady=(4, 0))
            self.btn_prepare = ttk.Button(
                act,
                text="🚀 一键拉取并完成全部体检（推荐点这里）",
                style="Primary.TButton",
                command=self._action_full_prepare,
            )
            self.btn_prepare.pack(side="left", padx=(0, 8))
            ttk.Button(act, text="刷新体检", style="Action.TButton", command=self._refresh_env_cards_async).pack(side="left", padx=(0, 8))
            ttk.Button(act, text="下一步：选方案 →", style="Action.TButton", command=lambda: self.nb.select(self.tab_cfg)).pack(side="right")

        def _build_tab_cfg(self) -> None:
            pad = self.tab_cfg.body

            c1 = self._make_card(pad)
            c1.pack(fill="x", pady=(0, 10))
            ttk.Label(c1.inner, text="1. 选择刷机方案（3 选 1）", style="Title.TLabel").pack(anchor="w", pady=(0, 6))
            for pid, title, desc in PROFILES_UI:
                rb = ttk.Radiobutton(c1.inner, text=title, value=pid, variable=self.profile_var, style="Card.TRadiobutton", command=self._invalidate_approved_plan)
                rb.pack(anchor="w", pady=(2, 0))
                ttk.Label(c1.inner, text="    " + desc, style="Muted.TLabel").pack(anchor="w", pady=(0, 4))

            ttk.Checkbutton(
                c1.inner,
                text="同时安装干净离线 OpenClash（仅含空模板，不含任何个人节点与订阅，方案 2 / 3 生效）",
                variable=self.openclash_var,
                style="Card.TCheckbutton",
                command=self._invalidate_approved_plan,
            ).pack(anchor="w", pady=(4, 0))

            c2 = self._make_card(pad)
            c2.pack(fill="x", pady=(0, 10))
            ttk.Label(c2.inner, text="2. 密码与备份路径设置（凭据全程经匿名管道传递，杜绝公共弱默认 Wi-Fi 密码）", style="Title.TLabel").pack(anchor="w", pady=(0, 8))

            r1 = tk.Frame(c2.inner, bg=PALETTE["card"])
            r1.pack(fill="x", pady=4)
            ttk.Label(r1, text="原厂后台密码 (192.168.0.1:8080)：", style="Card.TLabel", width=30).pack(side="left")
            self.webui_pw_entry = ttk.Entry(r1, textvariable=self.webui_pw_var, show="*", width=24)
            self.webui_pw_entry.pack(side="left", padx=(0, 8))
            ttk.Button(r1, text="立即验证密码（不重启）", style="Action.TButton", command=self._action_test_webui_pw).pack(side="left", padx=(0, 6))
            self.webui_pw_status = tk.Label(r1, text="机身背面贴纸密码", bg=PALETTE["card"], fg=PALETTE["muted"], font=("Microsoft YaHei UI", 9))
            self.webui_pw_status.pack(side="left")

            r2 = tk.Frame(c2.inner, bg=PALETTE["card"])
            r2.pack(fill="x", pady=4)
            ttk.Label(r2, text="OpenWrt 热点名称 (SSID)：", style="Card.TLabel", width=30).pack(side="left")
            ttk.Entry(r2, textvariable=self.wifi_ssid_var, width=22).pack(side="left", padx=(0, 12))
            ttk.Checkbutton(
                r2,
                text="自动生成本机唯一 16 位 Wi-Fi 密码（推荐）",
                variable=self.auto_wifi_pw_var,
                style="Card.TCheckbutton",
                command=self._toggle_wifi_pw_entry,
            ).pack(side="left")
            self.wifi_pw_entry = ttk.Entry(r2, textvariable=self.wifi_pw_var, show="*", width=18, state="disabled")
            self.wifi_pw_entry.pack(side="right")

            r3 = tk.Frame(c2.inner, bg=PALETTE["card"])
            r3.pack(fill="x", pady=4)
            ttk.Checkbutton(
                r3,
                text="自动生成高强度随机 OpenWrt 管理员 (root) 密码（推荐，刷完保存在本机凭据文件）",
                variable=self.gen_root_pw_var,
                style="Card.TCheckbutton",
                command=self._toggle_root_pw_entry,
            ).pack(side="left")
            self.custom_root_pw_entry = ttk.Entry(r3, textvariable=self.custom_root_pw_var, show="*", width=18, state="disabled")
            self.custom_root_pw_entry.pack(side="right")

            r4 = tk.Frame(c2.inner, bg=PALETTE["card"])
            r4.pack(fill="x", pady=4)
            ttk.Label(r4, text="本机备份与工作目录 (需 >= 15GB)：", style="Card.TLabel", width=30).pack(side="left")
            ttk.Entry(r4, textvariable=self.session_dir_var, width=40).pack(side="left", fill="x", expand=True, padx=(0, 8))
            ttk.Button(r4, text="选择目录...", command=self._choose_session_dir).pack(side="left")

            nav = tk.Frame(pad, bg=PALETTE["bg"])
            nav.pack(fill="x", pady=(4, 0))
            ttk.Button(nav, text="← 上一步", command=lambda: self.nb.select(self.tab_env)).pack(side="left")
            ttk.Button(nav, text="下一步：备份与刷机 →", style="Primary.TButton", command=lambda: self.nb.select(self.tab_run)).pack(side="right")

        def _build_tab_run(self) -> None:
            pad = self.tab_run.body

            warn = tk.Frame(pad, bg=PALETTE["warn_bg"], highlightbackground="#FCD34D", highlightthickness=1, padx=12, pady=8)
            warn.pack(fill="x", pady=(0, 10))
            warn_lbl = tk.Label(
                warn,
                text="安全红线：必须依次完成「① 只读备份 -> ② 离线干跑预览（绑定本机设备指纹与计划哈希）-> ③ 正式刷入」。刷写期间窗口会自动锁定，严禁拔线或断电！",
                bg=PALETTE["warn_bg"],
                fg=PALETTE["warn_fg"],
                font=("Microsoft YaHei UI", 9, "bold"),
                anchor="w",
                justify="left",
                wraplength=760,
            )
            warn_lbl.pack(fill="x")
            self._dynamic_wrap_labels.append((warn_lbl, 90))

            c1 = self._make_card(pad)
            c1.pack(fill="x", pady=(0, 8))
            r1 = tk.Frame(c1.inner, bg=PALETTE["card"])
            r1.pack(fill="x")
            left1 = tk.Frame(r1, bg=PALETTE["card"])
            left1.pack(side="left", fill="x", expand=True)
            ttk.Label(left1, text="步骤 A：全量只读备份原厂闪存（约 2~5 分钟，零写入风险）", style="Title.TLabel").pack(anchor="w")
            d1 = tk.Label(
                left1,
                text="读取本机全部可还原原厂分区并校验 SHA-256，备份完自动重启回原系统；若原目录已有备份将自动新建独立目录。",
                bg=PALETTE["card"],
                fg=PALETTE["muted"],
                font=("Microsoft YaHei UI", 9),
                anchor="w",
                justify="left",
                wraplength=600,
            )
            d1.pack(anchor="w", fill="x")
            self._dynamic_wrap_labels.append((d1, 340))
            ttk.Button(r1, text="打开备份目录", command=lambda: self._open_folder(Path(self.session_dir_var.get()) / "backup")).pack(side="right", padx=(6, 0))
            ttk.Button(r1, text="① 只读备份原厂分区", style="Action.TButton", command=self._action_backup_only).pack(side="right")

            c2 = self._make_card(pad)
            c2.pack(fill="x", pady=(0, 8))
            r2 = tk.Frame(c2.inner, bg=PALETTE["card"])
            r2.pack(fill="x")
            left2 = tk.Frame(r2, bg=PALETTE["card"])
            left2.pack(side="left", fill="x", expand=True)
            ttk.Label(left2, text="步骤 B：100% 离线干跑预览与安全审批（必做门禁）", style="Title.TLabel").pack(anchor="w")
            self.plan_badge_lbl = tk.Label(
                left2,
                text="尚未生成已批准的离线写入计划（完成步骤 B 后才能解锁步骤 C）",
                bg=PALETTE["card"],
                fg=PALETTE["warn_fg"],
                font=("Microsoft YaHei UI", 9),
                anchor="w",
                justify="left",
                wraplength=600,
            )
            self.plan_badge_lbl.pack(anchor="w", fill="x")
            self._dynamic_wrap_labels.append((self.plan_badge_lbl, 290))
            ttk.Button(r2, text="② 生成并核对干跑预览", style="Action.TButton", command=self._action_dry_run_plan).pack(side="right")

            c3 = self._make_card(pad)
            c3.pack(fill="x", pady=(0, 8))
            r3 = tk.Frame(c3.inner, bg=PALETTE["card"])
            r3.pack(fill="x")
            left3 = tk.Frame(r3, bg=PALETTE["card"])
            left3.pack(side="left", fill="x", expand=True)
            ttk.Label(left3, text="步骤 C：按已批准计划正式刷入与自动配网（约 5~10 分钟）", style="Title.TLabel").pack(anchor="w")
            d3 = tk.Label(
                left3,
                text="严格绑定步骤 B 的 flash_plan.json 摘要与本机设备指纹（方案 3 含二阶段写入安卓 _a），逐分区读回核对并保持防断网隔离。",
                bg=PALETTE["card"],
                fg=PALETTE["muted"],
                font=("Microsoft YaHei UI", 9),
                anchor="w",
                justify="left",
                wraplength=600,
            )
            d3.pack(anchor="w", fill="x")
            self._dynamic_wrap_labels.append((d3, 290))
            self.btn_execute = ttk.Button(r3, text="🚀 ③ 开始正式刷入", style="Primary.TButton", command=self._action_execute_auto)
            self.btn_execute.pack(side="right")

            c4 = self._make_card(pad, padding=10)
            c4.pack(fill="x")
            r4 = tk.Frame(c4.inner, bg=PALETTE["card"])
            r4.pack(fill="x")
            ttk.Label(r4, text="刷完快捷入口：", style="Title.TLabel").pack(side="left", padx=(0, 10))
            ttk.Button(r4, text="打开 OpenWrt 后台 (192.168.77.1)", command=lambda: webbrowser.open("http://192.168.77.1")).pack(side="left", padx=(0, 6))
            ttk.Button(r4, text="查看本机凭据文件", command=self._action_show_credentials).pack(side="left", padx=(0, 6))
            ttk.Button(r4, text="打开工作目录", command=lambda: self._open_folder(Path(self.session_dir_var.get()))).pack(side="left")

        def _build_tab_tools(self) -> None:
            pad = self.tab_tools.body

            c1 = self._make_card(pad)
            c1.pack(fill="x", pady=(0, 10))
            ttk.Label(c1.inner, text="1. 刷后只读巡检 & 电脑防断网隔离管理（绝不在线解除隔离）", style="Title.TLabel").pack(anchor="w", pady=(0, 8))
            row1 = tk.Frame(c1.inner, bg=PALETTE["card"])
            row1.pack(fill="x")
            ttk.Button(row1, text="一键只读体检 (probe)", style="Action.TButton", command=self._action_probe).pack(side="left", padx=(0, 8))
            ttk.Button(row1, text="修复 USB 网卡 + 防断网隔离", style="Action.TButton", command=self._action_repair_usb_net).pack(side="left", padx=(0, 8))
            ttk.Button(row1, text="拔线后恢复原网卡快照", command=self._action_restore_host_net).pack(side="left")

            c2 = self._make_card(pad)
            c2.pack(fill="x", pady=(0, 10))
            ttk.Label(c2.inner, text="2. 受控切回原厂安卓 (_a 槽) / 排障工具", style="Title.TLabel").pack(anchor="w", pady=(0, 6))
            d2 = tk.Label(
                c2.inner,
                text="平时切回原厂安卓只需长按机身按键 5 秒；若进不去系统，「受控切回原厂安卓」会绑定预览哈希并在同一 SPRD4 会话内校验本机备份、GPT、设备身份、写前槽位状态与读回 SHA-256 后再重启。",
                bg=PALETTE["card"],
                fg=PALETTE["muted"],
                font=("Microsoft YaHei UI", 9),
                anchor="w",
                justify="left",
                wraplength=760,
            )
            d2.pack(anchor="w", fill="x", pady=(0, 8))
            self._dynamic_wrap_labels.append((d2, 90))
            row2 = tk.Frame(c2.inner, bg=PALETTE["card"])
            row2.pack(fill="x")
            ttk.Button(row2, text="受控切回原厂安卓 (_a)", style="Action.TButton", command=self._action_rollback_a).pack(side="left", padx=(0, 8))
            ttk.Button(row2, text="重装展锐 WinUSB 驱动 (--force --all)", command=self._action_install_drivers).pack(side="left", padx=(0, 8))
            ttk.Button(row2, text="导出脱敏诊断报告 (.txt)", command=self._action_export_diag).pack(side="left")

        # ------------------------------------------------------------------
        # Thread-safe UI Queue & Logging
        # ------------------------------------------------------------------
        def _post_ui(self, event_type: str, payload: Any = None) -> None:
            if not self._closing:
                self.ui_queue.put((event_type, payload))

        def log_from_worker(
            self,
            msg: str,
            tag: str = "",
            *,
            secrets: list[str] | None = None,
            extra_redact_paths: list[str | Path] | None = None,
        ) -> None:
            clean = sanitize_diagnostic_text(msg, secrets=secrets, extra_redact_paths=extra_redact_paths)
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            self._post_ui("log", (f"[{ts}] {clean}", tag))

        def log_ui(self, msg: str, tag: str = "") -> None:
            secrets = [s for s in (self.webui_pw_var.get(), self.wifi_pw_var.get(), self.custom_root_pw_var.get()) if s]
            self.log_from_worker(msg, tag, secrets=secrets, extra_redact_paths=[self.workspace_dir, self.session_dir_var.get()])

        def _drain_ui_queue(self) -> None:
            if self._closing:
                return
            for _ in range(120):
                try:
                    ev, payload = self.ui_queue.get_nowait()
                except queue.Empty:
                    break
                if ev == "log":
                    line, tag = payload
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
                elif ev == "call":
                    try:
                        payload()
                    except Exception:
                        pass
            self.root.after(60, self._drain_ui_queue)

        def _clear_log(self) -> None:
            self.full_log_lines.clear()
            self.log_box.configure(state="normal")
            self.log_box.delete("1.0", "end")
            self.log_box.configure(state="disabled")

        def _invalidate_approved_plan(self) -> None:
            self._approved_plan = None
            if hasattr(self, "plan_badge_lbl"):
                self.plan_badge_lbl.configure(
                    text="参数已变更：请重新运行「② 生成并核对干跑预览」以绑定新计划摘要",
                    fg=PALETTE["warn_fg"],
                )

        def _set_busy(self, is_busy: bool, step_text: str = "", *, is_flash: bool = False) -> None:
            self.busy = is_busy
            self.active_is_flash = is_flash if is_busy else False
            if step_text:
                self.status_step_var.set(step_text)
            if is_busy:
                self.progress.start(12)
                if self.active_is_flash:
                    self.stop_btn.configure(text="刷写中禁止中断", state="disabled")
                else:
                    self.stop_btn.configure(text="停止当前任务", state="normal")
            else:
                self.progress.stop()
                self.stop_btn.configure(text="停止当前任务", state="disabled")

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
                self._on_mirror_choice_changed()
                self.nb.select(self.tab_env)
                self.log_ui(f"[INFO] 已自动切换大包下载加速镜像为：{self.mirror_choice_var.get()}，准备重试。", "INFO")
                self._action_full_prepare()
            elif action == "new_workdir":
                base = Path(self.session_dir_var.get())
                stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
                new_dir = base.parent / f"my-f50pro-{stamp}"
                self.session_dir_var.set(str(new_dir))
                self.log_ui("[OK] 已切换至全新独立设备工作目录。", "OK")
                self.nb.select(self.tab_run)
            else:
                self._action_export_diag()

        def _worker_env_from_cfg(self, cfg: dict[str, Any]) -> dict[str, str]:
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            env["PYTHONIOENCODING"] = "utf-8"
            mirror = cfg["mirror_prefix"]
            if mirror and mirror != "__OFFLINE__":
                env["F50PRO_GITHUB_MIRROR"] = mirror
            else:
                env.pop("F50PRO_GITHUB_MIRROR", None)
            return env

        def _toggle_root_pw_entry(self) -> None:
            self.custom_root_pw_entry.configure(state="disabled" if self.gen_root_pw_var.get() else "normal")

        def _toggle_wifi_pw_entry(self) -> None:
            self.wifi_pw_entry.configure(state="disabled" if self.auto_wifi_pw_var.get() else "normal")

        def _choose_session_dir(self) -> None:
            chosen = filedialog.askdirectory(initialdir=str(self.workspace_dir), title="选择备份与工作目录（建议纯英文路径且预留 >= 15 GB）")
            if chosen:
                self.session_dir_var.set(chosen)
                self._refresh_env_cards_async()

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
        # Live USB Radar
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
                    info = {"state": "query_error", "query_ok": False, "present_modes": [], "label": f"USB 检测异常: {exc}", "issues": []}
                finally:
                    self._radar_running = False
                self._post_ui("call", lambda: self._apply_usb_radar(info))

            threading.Thread(target=worker, daemon=True).start()

        def _apply_usb_radar(self, info: dict[str, Any]) -> None:
            self.last_usb_state = info
            state = info.get("state")
            issues = info.get("issues") or []
            has_err = any(i.get("severity") == "error" for i in issues)
            wrong_model = any(i.get("code") == "WRONG_DEVICE_MODEL" for i in issues)

            if wrong_model or has_err or not info.get("query_ok", True):
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
                self.radar_hint_lbl.configure(text="原厂后台在线（仅作状态提示；实际身份由备份与刷写前 GPT/指纹双重核验锁定）。", bg=bg, fg=PALETTE["text"])
            elif state == "openwrt":
                self.radar_hint_lbl.configure(text="OpenWrt 在线，可打开 http://192.168.77.1 或在「刷后体检」中一键检测。", bg=bg, fg=PALETTE["text"])
            elif state == "brom":
                self.radar_hint_lbl.configure(text="已处于展锐刷机口且全部接口均绑定 WinUSB，可执行受控操作。", bg=bg, fg=PALETTE["text"])

            self.btn_execute.configure(state="disabled" if wrong_model else "normal")

        # ------------------------------------------------------------------
        # Environment Cards Refresh
        # ------------------------------------------------------------------
        def _refresh_env_cards_async(self) -> None:
            session_dir = Path(self.session_dir_var.get())
            tools_dir = self.tools_dir
            kit_ver = self.active_kit_version

            def worker() -> None:
                admin = is_windows_admin()
                p_tools = check_native_tool_path_compat(tools_dir)
                p_sess = check_native_tool_path_compat(session_dir)
                path_ok = p_tools["ok"] and p_sess["ok"]
                path_msg = "通过" if path_ok else (p_tools.get("reason") or p_sess.get("reason") or "路径不兼容")
                disk = check_disk_space(session_dir)
                drv = inspect_unisoc_drivers()
                adb_pub = (Path.home() / ".android" / "adbkey.pub").is_file()
                spd_ok = (tools_dir / "host-tools-win64" / "spd_dump_251" / "spd_dump.exe").is_file()
                self._post_ui("call", lambda: self._render_env_cards(admin, path_ok, path_msg, disk, drv, adb_pub, spd_ok, kit_ver))

            threading.Thread(target=worker, daemon=True).start()

        def _render_env_cards(
            self,
            admin: bool,
            path_ok: bool,
            path_msg: str,
            disk: dict[str, Any],
            drv: dict[str, Any],
            adb_pub: bool,
            spd_ok: bool,
            kit_ver: str,
        ) -> None:
            self.kit_ver_badge.configure(text=f"工具脚本: {kit_ver}")
            self.env_labels["admin"].configure(
                text="通过（已获得管理员权限）" if admin else "未通过：请关闭程序并右键「以管理员身份运行」",
                fg=PALETTE["ok_fg"] if admin else PALETTE["err_fg"],
            )
            self.env_labels["path"].configure(
                text="通过（底层工具路径兼容）" if path_ok else path_msg,
                fg=PALETTE["ok_fg"] if path_ok else PALETTE["err_fg"],
            )
            self.env_labels["disk"].configure(
                text=f"{'通过' if disk['ok'] else '空间不足'}：当前剩余 {disk['free_gb']} GB",
                fg=PALETTE["ok_fg"] if disk["ok"] else PALETTE["err_fg"],
            )
            self.env_labels["kit"].configure(
                text=(
                    f"已就绪（{kit_ver}，Windows 工具包已就位）"
                    if spd_ok
                    else f"待拉取（内置不可变基线 {kit_ver}，点击下方一键拉取并体检）"
                ),
                fg=PALETTE["ok_fg"] if spd_ok else PALETTE["warn_fg"],
            )
            conflicts = drv.get("conflicting_serial_infs") or []
            if drv.get("installed") and not conflicts:
                drv_txt, drv_fg = f"已核验入库（4D00 & 4D03 WinUSB，共 {len(drv.get('winusb_infs') or [])} 个 INF）", PALETTE["ok_fg"]
            elif drv.get("installed") and conflicts:
                drv_txt = f"WinUSB 已入库，但检测到 {len(conflicts)} 个旧串口驱动可能冲突，若抓口超时请用 Zadig 替换"
                drv_fg = PALETTE["warn_fg"]
            else:
                drv_txt = f"未完整入库（4D00={drv.get('has_4d00_winusb')}, 4D03={drv.get('has_4d03_winusb')}；点击一键体检将认证预装）"
                drv_fg = PALETTE["warn_fg"]
            self.env_labels["driver"].configure(text=drv_txt, fg=drv_fg)
            self.env_labels["adbkey"].configure(
                text="已就绪 (~/.android/adbkey.pub)" if adb_pub else "尚未生成（点击一键体检将自动生成）",
                fg=PALETTE["ok_fg"] if adb_pub else PALETTE["warn_fg"],
            )

        # ------------------------------------------------------------------
        # Subprocess Worker Runner (stdin pipe secrets + bounded timeout watchdog)
        # ------------------------------------------------------------------
        def _run_subprocess_streaming(
            self,
            cmd: list[str],
            *,
            cfg: dict[str, Any],
            stdin_secrets: dict[str, str] | None = None,
            timeout_sec: float | None = 300.0,
        ) -> tuple[int, str]:
            out_lines: list[str] = []
            use_stdin = stdin_secrets is not None
            redact_paths = [self.workspace_dir, cfg["session_dir"], cfg["tools_dir"], cfg["cache_dir"]]
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE if use_stdin else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=self._worker_env_from_cfg(cfg),
                **_no_window_kwargs(),
            )
            self.active_proc = proc
            timed_out = threading.Event()
            timer: threading.Timer | None = None

            if timeout_sec is not None:
                def _watchdog() -> None:
                    timed_out.set()
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                    try:
                        proc.wait(timeout=5.0)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass

                timer = threading.Timer(timeout_sec, _watchdog)
                timer.daemon = True
                timer.start()
            try:
                if use_stdin and proc.stdin is not None:
                    try:
                        proc.stdin.write(json.dumps(stdin_secrets, ensure_ascii=False))
                    except BrokenPipeError:
                        pass
                    finally:
                        try:
                            proc.stdin.close()
                        except Exception:
                            pass
                assert proc.stdout is not None
                for raw in proc.stdout:
                    line = raw.rstrip("\r\n")
                    out_lines.append(line)
                    self.log_from_worker(line, secrets=cfg["secrets"], extra_redact_paths=redact_paths)
                rc = proc.wait()
            finally:
                if timer is not None:
                    timer.cancel()
                self.active_proc = None
            if timed_out.is_set():
                out_lines.append(f"[ERR] Non-flash worker subprocess timed out after {int(timeout_sec or 0)}s and was terminated.")
                return 124, "\n".join(out_lines)
            return rc, "\n".join(out_lines)

        def _launch_bg_task(
            self,
            title: str,
            fn: Callable[[dict[str, Any]], Any],
            *,
            is_flash: bool = False,
            on_success: Callable[[Any], None] | None = None,
        ) -> None:
            if self.busy:
                messagebox.showwarning("任务进行中", "当前已有任务在执行，请等待完成。")
                return
            try:
                cfg = self._snapshot_config()
            except Exception as exc:
                messagebox.showerror("配置无效", str(exc))
                return
            self._hide_diag_banner()
            self._set_busy(True, title, is_flash=is_flash)

            def wrapper() -> None:
                succeeded = False
                result: Any = None
                redact_paths = [self.workspace_dir, cfg["session_dir"], cfg["tools_dir"], cfg["cache_dir"]]
                try:
                    result = fn(cfg)
                    succeeded = True
                except _DiagnosedTaskError as dexc:
                    self.log_from_worker(f"[ERR] {dexc}", "ERR", secrets=cfg["secrets"], extra_redact_paths=redact_paths)
                    diag = dexc.diag
                    self._post_ui("call", lambda: self._show_diag_banner(diag))
                except Exception as exc:
                    err_text = str(exc)
                    self.log_from_worker(f"[ERR] {err_text}", "ERR", secrets=cfg["secrets"], extra_redact_paths=redact_paths)
                    diag = diagnose_failure(err_text)
                    self._post_ui("call", lambda: self._show_diag_banner(diag))
                finally:
                    def finish() -> None:
                        self._set_busy(False, "就绪")
                        self._refresh_env_cards_async()
                        if succeeded and on_success is not None:
                            on_success(result)

                    self._post_ui("call", finish)

            threading.Thread(target=wrapper, daemon=True).start()

        def _action_stop_task(self) -> None:
            if self.active_is_flash:
                messagebox.showerror("禁止中断", "当前处于写入/校验阶段，禁止强行停止！")
                return
            if not self.active_proc:
                return
            try:
                self.active_proc.terminate()
                self.log_ui("[WARN] 用户已终止当前非写入任务。", "WARN")
            except Exception as exc:
                self.log_ui(f"[ERR] 停止进程失败：{exc}", "ERR")

        # ------------------------------------------------------------------
        # User Actions
        # ------------------------------------------------------------------
        def _action_full_prepare(self) -> None:
            def task(cfg: dict[str, Any]) -> None:
                for p in (cfg["tools_dir"], cfg["session_dir"]):
                    compat = check_native_tool_path_compat(p)
                    if not compat["ok"]:
                        raise RuntimeError(compat["reason"])

                if not is_windows_admin():
                    self.log_from_worker("[WARN] 当前非管理员权限，安装驱动和网卡隔离可能失败，建议右键以管理员身份运行！", "WARN")

                disk = check_disk_space(cfg["session_dir"])
                if not disk["ok"]:
                    raise RuntimeError(f"磁盘剩余空间不足：仅剩 {disk['free_gb']} GB，至少需要 15 GB。")

                kit_root = cfg["kit_root"]
                kit_ver = cfg["kit_version"]

                # 1. Auto-update source kit ONLY via official direct GitHub trust anchor + protocol/policy gate
                if cfg["offline"]:
                    self.log_from_worker(f"[INFO] 离线模式：使用内置不可变基线脚本（{kit_ver}）。", "INFO")
                else:
                    self.log_from_worker("直连官方 GitHub 检查最新兼容版本（摘要不经过第三方镜像，且拒绝降级与非 25.12.5 策略）...", "INFO")
                    try:
                        rel = fetch_latest_release_info()
                        self.log_from_worker(f"[OK] 官方 GitHub 最新版本：{rel['tag']} ({rel['name']})", "OK")
                        dl = download_and_verify_kit_release(
                            rel,
                            kit_store_dir=self.kit_store_dir,
                            mirror_prefix=cfg["mirror_prefix"],
                            min_tag=cfg["bundled_kit_version"],
                            log_cb=lambda m: self.log_from_worker(m, secrets=cfg["secrets"]),
                        )
                        kit_root = Path(dl["kit_root"])
                        kit_ver = str(dl["tag"])
                        self._post_ui("call", lambda kr=kit_root, kv=kit_ver: self._set_active_kit(kr, kv))
                    except Exception as exc:
                        self.log_from_worker(
                            f"[WARN] 未切换在线更新脚本，将继续使用内置已校验脚本（{kit_ver}）：{exc}",
                            "WARN",
                        )

                # 2. Fetch & SHA-256 verify required win64 tools + selected firmware packs (binds executables directly to zip!)
                args = [
                    "fetch-assets",
                    "--host-platform",
                    "win64",
                    "--profile",
                    cfg["profile"],
                    "--cache-dir",
                    str(cfg["cache_dir"]),
                    "--tools-dir",
                    str(cfg["tools_dir"]),
                ]
                if not cfg["openclash"]:
                    args.append("--no-openclash")
                if cfg["offline"]:
                    args.append("--offline-only")
                self.log_from_worker(f"校验并准备 Windows 工具包与固件包（方案：{cfg['profile']}）...", "INFO")
                rc, out = self._run_subprocess_streaming(
                    build_worker_command("--run-kit", kit_root, args), cfg=cfg, timeout_sec=600.0
                )
                if rc != 0:
                    raise RuntimeError(f"资源包拉取或校验失败（exit={rc}）：\n{out[-1200:]}")

                # 3. Verify BOTH Driver Store AND live BROM USB binding; install via manifest-authenticated exe if needed
                drv = inspect_unisoc_drivers()
                live_usb = detect_usb_device_state(probe_network=False)
                live_brom_conflict = (not live_usb.get("query_ok", True)) or any(
                    i.get("code") == "BROM_DRIVER_NOT_WINUSB" for i in (live_usb.get("issues") or [])
                )
                if drv.get("installed") and not live_brom_conflict:
                    self.log_from_worker("[OK] 展锐 WinUSB 驱动（1782:4D00 & 4D03）已入库且无实机冲突绑定。", "OK")
                else:
                    res = install_unisoc_winusb_drivers(
                        cfg["tools_dir"],
                        manifest_path=kit_root / "assets" / "release-manifest.json",
                        cache_dir=cfg["cache_dir"],
                        log_cb=lambda m: self.log_from_worker(m),
                    )
                    if not res.get("ok"):
                        raise RuntimeError(res.get("error") or f"展锐 WinUSB 驱动安装未通过核验：{res.get('output', '')}")
                    self.log_from_worker("[OK] 展锐 WinUSB 驱动（1782:4D00 & 4D03）已认证预装并复核通过！", "OK")

                # 4. Auto-generate ADB RSA keypair
                adb_res = ensure_adb_pubkey(cfg["tools_dir"])
                if not adb_res.get("ok"):
                    raise RuntimeError(str(adb_res.get("error")))
                self.log_from_worker("[OK] 本机 ADB RSA 公钥 (~/.android/adbkey.pub) 已就绪。", "OK")

                # 5. Strict preflight verification
                pf_args = [
                    "preflight",
                    "--strict",
                    "--operation",
                    "auto",
                    "--profile",
                    cfg["profile"],
                    "--tools-dir",
                    str(cfg["tools_dir"]),
                ]
                rc_pf, out_pf = self._run_subprocess_streaming(
                    build_worker_command("--run-kit", kit_root, pf_args), cfg=cfg, timeout_sec=120.0
                )
                if rc_pf != 0:
                    raise RuntimeError(f"环境预检未通过（exit={rc_pf}）：\n{out_pf[-1200:]}")
                self.log_from_worker("[OK] 全部环境体检通过！请核对方案和密码后依次执行备份 -> 干跑预览 -> 正式刷入。", "OK")
                self._post_ui(
                    "call",
                    lambda kv=kit_ver: messagebox.showinfo("环境准备完成", f"环境已全部通过校验！（脚本版本：{kv}）\n请切换到「② 方案与密码设置」确认参数。"),
                )

            self._launch_bg_task("正在拉取校验并完成全部环境体检...", task)

        def _set_active_kit(self, kit_root: Path, kit_ver: str) -> None:
            changed = Path(kit_root) != Path(self.active_kit_root)
            self.active_kit_root = kit_root
            self.active_kit_version = kit_ver
            self.kit_ver_badge.configure(text=f"工具脚本: {kit_ver}")
            if changed:
                self._invalidate_approved_plan()

        def _action_install_drivers(self) -> None:
            def task(cfg: dict[str, Any]) -> None:
                # Security rule (New P0-1): ALWAYS re-authenticate host_tools_win64 pack via fetch-assets & manifest zip
                # BEFORE launching elevated qmk_driver_installer.exe (never trust an existing file by presence alone!).
                self.log_from_worker("[INFO] 校验并认证 host_tools_win64 驱动安装包哈希...", "INFO")
                args = [
                    "fetch-assets",
                    "--host-platform",
                    "win64",
                    "--profile",
                    "none",
                    "--packs",
                    "host_tools_win64",
                    "--cache-dir",
                    str(cfg["cache_dir"]),
                    "--tools-dir",
                    str(cfg["tools_dir"]),
                ]
                if cfg["offline"]:
                    args.append("--offline-only")
                rc, out = self._run_subprocess_streaming(
                    build_worker_command("--run-kit", cfg["kit_root"], args), cfg=cfg, timeout_sec=300.0
                )
                if rc != 0:
                    raise RuntimeError(f"认证驱动工具包失败：\n{out[-1000:]}")
                res = install_unisoc_winusb_drivers(
                    cfg["tools_dir"],
                    manifest_path=cfg["kit_root"] / "assets" / "release-manifest.json",
                    cache_dir=cfg["cache_dir"],
                    log_cb=lambda m: self.log_from_worker(m),
                )
                if not res.get("ok"):
                    raise RuntimeError(res.get("error") or f"驱动安装未通过核验：\n{res.get('output', '')}")
                self.log_from_worker("[OK] 展锐 BROM (1782:4D00) 与 Boot Diag (1782:4D03) WinUSB 驱动已认证入库且无实机冲突！", "OK")
                self._post_ui("call", lambda: messagebox.showinfo("驱动安装成功", "已核验 1782:4D00 与 1782:4D03 WinUSB 驱动均已入库且无实机冲突！"))

            self._launch_bg_task("正在认证并安装展锐 WinUSB 驱动 (--force --all)...", task)

        def _action_generate_adb_key(self) -> None:
            def task(cfg: dict[str, Any]) -> None:
                res = ensure_adb_pubkey(cfg["tools_dir"])
                if not res.get("ok"):
                    raise RuntimeError(str(res.get("error")))
                self.log_from_worker("[OK] 本机 ADB RSA 公钥 (~/.android/adbkey.pub) 已就绪。", "OK")

            self._launch_bg_task("正在生成 ADB RSA 密钥...", task)

        def _action_test_webui_pw(self) -> None:
            pw = self.webui_pw_var.get()
            self.webui_pw_status.configure(text="验证中...", fg=PALETTE["info_fg"])

            def worker() -> None:
                res = test_webui_password(pw)

                def finish() -> None:
                    if res.get("ok"):
                        self.webui_pw_status.configure(text="✓ 密码验证通过", fg=PALETTE["ok_fg"])
                        self.log_ui(f"[OK] {res['message']}", "OK")
                    else:
                        self.webui_pw_status.configure(text="✗ 验证失败", fg=PALETTE["err_fg"])
                        self.log_ui(f"[ERR] {res['message']}", "ERR")
                        messagebox.showwarning("原厂后台密码校验未通过", res["message"])

                self._post_ui("call", finish)

            threading.Thread(target=worker, daemon=True).start()

        def _validate_common_form(self, *, require_wifi: bool = False) -> bool:
            if any(i.get("code") == "WRONG_DEVICE_MODEL" for i in (self.last_usb_state.get("issues") or [])):
                messagebox.showerror("危险拦截", "检测到非 F50 Pro (MU3356) 机型，已禁止操作！")
                return False
            for p in (self.tools_dir, Path(self.session_dir_var.get())):
                compat = check_native_tool_path_compat(p)
                if not compat["ok"]:
                    messagebox.showerror("路径兼容性问题", compat["reason"])
                    return False
            if require_wifi and self.profile_var.get() in ("2-dual-stock-openwrt", "3-dual-full"):
                if not self.auto_wifi_pw_var.get():
                    wpw = self.wifi_pw_var.get()
                    if not (8 <= len(wpw) <= 63) or any(not (32 <= ord(c) <= 126) for c in wpw):
                        messagebox.showwarning(
                            "必须设置有效唯一 Wi-Fi 密码",
                            "为避免暴露公开默认密码，请勾选「自动生成本机唯一 16 位 Wi-Fi 密码」，或填写 8~63 位标准可见 ASCII 字符的自定义热点密码。",
                        )
                        self.nb.select(self.tab_cfg)
                        return False
            if not self.gen_root_pw_var.get() and self.custom_root_pw_var.get() == "":
                messagebox.showwarning("缺少 root 密码", "请勾选「自动生成高强度随机密码」，或填写自定义 OpenWrt 管理员密码。")
                self.nb.select(self.tab_cfg)
                return False
            return True

        def _action_backup_only(self) -> None:
            if not self._validate_common_form():
                return
            session_dir = Path(self.session_dir_var.get())
            backup_dir = session_dir / "backup"
            if backup_dir.exists() and any(backup_dir.iterdir()):
                stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
                new_session = session_dir.parent / f"my-f50pro-{stamp}"
                if not messagebox.askyesno(
                    "原目录已有备份",
                    f"当前目录已有旧备份。\n为保护旧备份不被覆盖，是否自动切换到新目录：\n{new_session}\n并重新备份？",
                ):
                    return
                self.session_dir_var.set(str(new_session))
            if self.webui_pw_var.get() == "":
                if not messagebox.askyesno(
                    "未填原厂后台密码",
                    "未填写原厂后台密码时，脚本无法自动触发重启进下载口（需出现 Waiting for boot_diag 时手动进下载口）。\n是否继续？",
                ):
                    self.nb.select(self.tab_cfg)
                    return

            def task(cfg: dict[str, Any]) -> None:
                bdir = cfg["session_dir"] / "backup"
                args = [
                    "backup",
                    "--output-dir",
                    str(bdir),
                    "--tools-dir",
                    str(cfg["tools_dir"]),
                    "--authorize-device-reboot",
                ]
                secrets_payload: dict[str, str] | None = None
                if cfg["webui_pw"] != "":
                    args.append("--secrets-stdin")
                    secrets_payload = {"webui_password": cfg["webui_pw"]}
                self.log_from_worker("开始只读全量备份原厂闪存（约 2~5 分钟，期间设备会自动重启进下载模式，请勿拔线）...", "INFO")
                rc, out = self._run_subprocess_streaming(
                    build_worker_command("--run-kit", cfg["kit_root"], args),
                    cfg=cfg,
                    stdin_secrets=secrets_payload,
                    timeout_sec=1800.0,
                )
                if rc != 0:
                    raise RuntimeError(f"原厂分区备份失败（exit={rc}）：\n{out[-1500:]}")
                self.log_from_worker("[OK] 原厂全量备份成功并校验通过（请继续点击「② 生成并核对干跑预览」）。", "OK")
                self._post_ui(
                    "call",
                    lambda d=bdir: messagebox.showinfo("原厂备份成功", f"原厂分区已完整备份并校验通过！\n路径：{d}\n下一步请点击「② 生成并核对干跑预览」。"),
                )

            self._launch_bg_task("正在全量只读备份原厂分区（切勿拔线）...", task)

        def _action_dry_run_plan(self) -> None:
            if not self._validate_common_form():
                return

            def task(cfg: dict[str, Any]) -> None:
                prof = cfg["profile"]
                args = [
                    "plan",
                    "--profile",
                    prof,
                    "--work-dir",
                    str(cfg["session_dir"]),
                    "--tools-dir",
                    str(cfg["tools_dir"]),
                    "--cache-dir",
                    str(cfg["cache_dir"]),
                ]
                if cfg["openclash"] and prof in ("2-dual-stock-openwrt", "3-dual-full"):
                    args.append("--openclash")
                self.log_from_worker("正在执行 100% 离线干跑预览（不接触设备、不联网）...", "INFO")
                rc, out = self._run_subprocess_streaming(
                    build_worker_command("--run-kit", cfg["kit_root"], args), cfg=cfg, timeout_sec=180.0
                )
                if rc != 0:
                    raise RuntimeError(f"干跑预览失败（exit={rc}）：\n{out[-1500:]}")
                parsed = extract_last_json_object(out) or {}
                st = parsed.get("status")
                if st == "BACKUP_REQUIRED":
                    self._post_ui(
                        "call",
                        lambda: messagebox.showinfo("需先完成步骤 A（只读备份）", "当前工作目录尚无已校验的原厂备份。\n请先点击「① 只读备份原厂分区」，再生成干跑预览。"),
                    )
                    return
                if st == "OFFLINE_ASSETS_REQUIRED":
                    raise RuntimeError("缺少所需离线资源包，请先在「① 环境体检」中点击「一键拉取并完成全部体检」。")
                if st != "DRY_RUN_READY":
                    raise RuntimeError(f"干跑预览返回非预期状态：{st}")

                bld = parsed.get("build") or {}
                fl = parsed.get("flash") or {}
                ins = parsed.get("inspect") or {}
                plan_sha = str(bld.get("plan_sha256") or "")
                unit_sha = str(bld.get("unit_identity_sha256") or "")
                if len(plan_sha) != 64:
                    raise RuntimeError("干跑结果缺少有效 flash_plan.json SHA-256 摘要，无法授权。")
                ops = fl.get("operations") or []
                op_lines = "\n".join(
                    f"  - {o.get('op')} {o.get('partition')} ({round(int(o.get('size_bytes') or 0) / (1024 * 1024), 2)} MiB)"
                    for o in ops
                )
                a_stage = bld.get("android_a_stage") or {}
                a_stage_txt = ""
                if a_stage.get("apply_from_openwrt"):
                    t_mb = round(int(a_stage.get("trustos_a_bytes") or 0) / (1024 * 1024), 2)
                    i_mb = round(int(a_stage.get("init_boot_a_bytes") or 0) / (1024 * 1024), 2)
                    a_stage_txt = f"\n• 方案 3 二阶段安卓 _a 写入（OpenWrt 启动后经读回核验写入）：trustos_a ({t_mb} MiB)、init_boot_a ({i_mb} MiB)"
                board_note = str(bld.get("board_id") or "离线阶段未读取（OpenWrt 连机后实时核验 B28=6 / B15=1）")
                write_mb = round(int(bld.get("total_brom_write_bytes") or 0) / (1024 * 1024), 2)
                approved = {
                    "profile": prof,
                    "session_dir": str(cfg["session_dir"]),
                    "openclash": cfg["openclash"],
                    "kit_root": str(cfg["kit_root"]),
                    "plan_sha256": plan_sha,
                    "unit_identity_sha256": unit_sha,
                    "board_note": board_note,
                    "android_a_stage_summary": a_stage_txt,
                    "trustos_offset": ((ins.get("trustos_a") or {}).get("patch_code_offset")),
                    "write_mb": write_mb,
                    "operations": ops,
                }
                summary = (
                    f"离线干跑预览通过（可安全进入步骤 C）\n\n"
                    f"• 刷机方案：{prof}\n"
                    f"• 主板变体 (board_id)：{board_note}\n"
                    f"• 本机指纹摘要：{unit_sha[:16]}...\n"
                    f"• 计划哈希 (plan_sha256)：{plan_sha[:16]}...\n"
                    f"• TrustOS 补丁偏移：{approved['trustos_offset']}\n"
                    f"• BROM 一阶段写入总量：{write_mb} MiB（受保护分区写入数：0）\n"
                    f"• BROM 写入分区清单：\n{op_lines or '  (无 BROM 写入)'}"
                    f"{a_stage_txt}\n"
                )
                self.log_from_worker(f"[OK] 离线干跑预览通过：plan_sha256={plan_sha[:16]}...（已绑定批准计划）", "OK")

                def apply_approval() -> None:
                    self._approved_plan = approved
                    self.plan_badge_lbl.configure(
                        text=f"✓ 已通过干跑预览（plan_sha256={plan_sha[:12]}... · 设备指纹={unit_sha[:12]}... · 共 {len(ops)} 项 BROM 操作）",
                        fg=PALETTE["ok_fg"],
                    )
                    messagebox.showinfo("离线干跑预览通过", summary)

                self._post_ui("call", apply_approval)

            self._launch_bg_task("正在生成并核对离线干跑预览...", task)

        def _check_reconcile_write_intent(self, session_dir: Path) -> bool:
            """Block new flash/rollback attempts if a previous write intent did not finish cleanly until operator reconciles."""
            for sub in ("flash-run", "rollback-run"):
                ip = session_dir / "build" / sub / "active_write_intent.json"
                if not ip.is_file():
                    continue
                try:
                    rec = json.loads(ip.read_text(encoding="utf-8"))
                except Exception:
                    rec = {"state": "unknown"}
                msg = (
                    f"安全拦截：检测到上一次写入/回退会话尚未闭环（{sub}/active_write_intent.json）：\n"
                    f"• 操作：{rec.get('operation', sub)}\n"
                    f"• 状态：{rec.get('state', 'unknown')}\n"
                    f"• 会话编号：{rec.get('attempt_id', '')}\n\n"
                    f"请先核查对应目录下的 flash_state.json / rollback_state.json 与设备当前供电/连接状态。\n"
                    f"确认设备状态已核查完毕、允许清除未闭环锁并继续新的写入吗？"
                )
                if not messagebox.askyesno("未闭环写入状态核查", msg, icon="warning"):
                    return False
                ip.unlink(missing_ok=True)
            return True

        def _action_execute_auto(self) -> None:
            if not self._validate_common_form(require_wifi=True):
                return
            if not self._check_reconcile_write_intent(Path(self.session_dir_var.get())):
                return
            cur_session = str(Path(self.session_dir_var.get()))
            cur_prof = self.profile_var.get()
            cur_oc = bool(self.openclash_var.get())
            ap = self._approved_plan
            if (
                not ap
                or ap.get("profile") != cur_prof
                or ap.get("session_dir") != cur_session
                or ap.get("openclash") != cur_oc
                or ap.get("kit_root") != str(self.active_kit_root)
            ):
                messagebox.showwarning(
                    "必须先通过离线干跑预览",
                    "安全门禁要求：正式刷入前必须针对当前方案、工作目录与脚本版本完成「① 只读备份」和「② 生成并核对干跑预览」。",
                )
                return

            ops = ap.get("operations") or []
            op_names = ", ".join(str(o.get("partition")) for o in ops) or "(仅配网)"
            a_stage_note = ap.get("android_a_stage_summary") or ""
            confirm_msg = (
                f"即将按已批准的干跑计划正式刷入，请核对最终绑定信息：\n\n"
                f"• 刷机方案：{cur_prof}\n"
                f"• 主板变体：{ap.get('board_note', 'MU3356')}\n"
                f"• 离线 OpenClash：{'是' if (cur_oc and cur_prof != '1-android-ufi') else '否'}\n"
                f"• 本机指纹摘要：{ap['unit_identity_sha256'][:16]}...\n"
                f"• 批准计划哈希：{ap['plan_sha256'][:16]}...\n"
                f"• BROM 一阶段写入分区：{op_names}（总计 {ap['write_mb']} MiB，受保护分区 = 0）"
                f"{a_stage_note}\n\n"
                f"⚠️ 刷机期间窗口将自动锁定防止误关闭，绝对不要拔掉 USB 线或断电！\n确认正式执行吗？"
            )
            if not messagebox.askyesno("正式刷机最终审批确认", confirm_msg, icon="warning"):
                return

            approved_sha = str(ap["plan_sha256"])

            def task(cfg: dict[str, Any]) -> None:
                prof = cfg["profile"]
                args = [
                    "auto",
                    "--profile",
                    prof,
                    "--work-dir",
                    str(cfg["session_dir"]),
                    "--tools-dir",
                    str(cfg["tools_dir"]),
                    "--cache-dir",
                    str(cfg["cache_dir"]),
                    "--reuse-backup",
                    "--expected-plan-sha256",
                    approved_sha,
                    "--secrets-stdin",
                    "--execute",
                ]
                if cfg["offline"]:
                    args.append("--offline-only")
                secrets_payload: dict[str, str] = {}
                if cfg["webui_pw"] != "":
                    secrets_payload["webui_password"] = cfg["webui_pw"]
                if prof in ("2-dual-stock-openwrt", "3-dual-full"):
                    args += ["--wifi-ssid", cfg["wifi_ssid"]]
                    effective_wifi_pw = _generate_strong_wifi_password(16) if cfg["auto_wifi_pw"] else cfg["wifi_pw"]
                    secrets_payload["wifi_password"] = effective_wifi_pw
                    cfg["secrets"] = [*cfg["secrets"], effective_wifi_pw]
                    if cfg["gen_root_pw"]:
                        args.append("--generate-password")
                    else:
                        secrets_payload["root_password"] = cfg["custom_root_pw"]
                    if cfg["openclash"]:
                        args.append("--openclash")

                # Archive any stale failure report from a prior attempt and persist write intent BEFORE launching worker
                run_dir = cfg["session_dir"] / "build" / "flash-run"
                run_dir.mkdir(parents=True, exist_ok=True)
                fr_path = run_dir / "flash_failure_report.json"
                if fr_path.is_file():
                    try:
                        fr_path.replace(run_dir / "flash_failure_report.prev.json")
                    except OSError:
                        fr_path.unlink(missing_ok=True)
                intent_path = run_dir / "active_write_intent.json"
                attempt_id = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + "-" + _secrets.token_hex(4)
                intent_path.write_text(
                    json.dumps({"attempt_id": attempt_id, "operation": "auto_flash", "plan_sha256": approved_sha, "state": "in_progress"}, indent=2) + "\n",
                    encoding="utf-8",
                )

                self.log_from_worker(
                    f"正式按已批准计划（plan_sha256={approved_sha[:12]}...）启动刷入与自动配网，窗口已锁定，切勿拔线...",
                    "INFO",
                )
                # Security rule (P0): NEVER attach a blind GUI kill-timer to an active flash!
                # Core flash_images.py enforces phase-aware per-command timeouts and persists flash_state.json safely.
                rc, out = self._run_subprocess_streaming(
                    build_worker_command("--run-kit", cfg["kit_root"], args),
                    cfg=cfg,
                    stdin_secrets=secrets_payload,
                    timeout_sec=None,
                )
                if rc != 0:
                    fail_rep = None
                    if fr_path.is_file():
                        try:
                            fail_rep = json.loads(fr_path.read_text(encoding="utf-8"))
                        except Exception:
                            pass
                    intent_path.write_text(
                        json.dumps({"attempt_id": attempt_id, "operation": "auto_flash", "state": "failed_reconcile_required", "rc": rc, "has_failure_report": fail_rep is not None}, indent=2) + "\n",
                        encoding="utf-8",
                    )
                    diag = diagnose_failure(out, failure_report=fail_rep)
                    raise _DiagnosedTaskError(f"刷机流程中断（exit={rc}）：{diag['title']}", diag)

                intent_path.unlink(missing_ok=True)
                self.log_from_worker("[OK] 恭喜！一键刷机、自动配网与端到端验收全部通过！", "OK")
                self._post_ui("call", lambda sdir=cfg["session_dir"]: self._show_success_credentials_popup(sdir))

            self._launch_bg_task("正在按已批准计划刷入与配网（窗口已锁定，切勿拔线）...", task, is_flash=True)

        def _show_success_credentials_popup(self, session_dir: Path) -> None:
            ow_cred = session_dir / "build" / "openwrt-credentials.json"
            and_cred = session_dir / "build" / "android-ttyd-credentials.json"
            lines = ["刷机与自动配网已全部完成！"]
            if ow_cred.is_file():
                try:
                    data = json.loads(ow_cred.read_text(encoding="utf-8"))
                    lines.append(
                        f"\n• OpenWrt 管理地址：http://192.168.77.1"
                        f"\n• 用户名：root"
                        f"\n• 管理员密码：{data.get('password', '(见文件)')}"
                    )
                    if data.get("wifi_ssid"):
                        lines.append(f"• OpenWrt Wi-Fi 名称：{data['wifi_ssid']}")
                    if data.get("wifi_password"):
                        lines.append(f"• OpenWrt Wi-Fi 密码：{data['wifi_password']}")
                except Exception:
                    lines.append(f"\n• OpenWrt 凭据文件：{ow_cred}")
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
                msgs.append(f"[OpenWrt 凭据文件]\n{ow_cred}\n{ow_cred.read_text(encoding='utf-8')}")
            if and_cred.is_file():
                msgs.append(f"[安卓 ttyd 口令文件]\n{and_cred}\n{and_cred.read_text(encoding='utf-8')}")
            if not msgs:
                messagebox.showinfo("暂无凭据文件", f"在 {session_dir / 'build'} 下尚未找到生成的凭据文件（需完成刷机配网后生成）。")
                return
            messagebox.showinfo("本机保存的设备登录凭据", "\n\n".join(msgs))

        def _action_probe(self) -> None:
            def task(cfg: dict[str, Any]) -> None:
                cred_file = cfg["session_dir"] / "build" / "openwrt-credentials.json"
                args = ["probe", "--profile", cfg["profile"], "--tools-dir", str(cfg["tools_dir"])]
                secrets_payload: dict[str, str] | None = None
                if cred_file.is_file():
                    args += ["--credentials-file", str(cred_file)]
                elif not cfg["gen_root_pw"] and cfg["custom_root_pw"] != "":
                    args.append("--secrets-stdin")
                    secrets_payload = {"root_password": cfg["custom_root_pw"]}
                if cfg["openclash"] and cfg["profile"] != "1-android-ufi":
                    args.append("--openclash")
                rc, _out = self._run_subprocess_streaming(
                    build_worker_command("--run-kit", cfg["kit_root"], args),
                    cfg=cfg,
                    stdin_secrets=secrets_payload,
                    timeout_sec=180.0,
                )
                if rc != 0:
                    raise RuntimeError(f"只读巡检存在异常项（exit={rc}），请查看上方日志细节。")
                self.log_from_worker("[OK] 只读巡检 PASS：双系统状态与宿主机防断网隔离全部健康！", "OK")

            self._launch_bg_task("正在执行刷后只读体检 (probe)...", task)

        def _action_repair_usb_net(self) -> None:
            def task(cfg: dict[str, Any]) -> None:
                self.log_from_worker("正在按当前设备模式执行隔离网卡修复与路由/连通性核验...", "INFO")
                snap = cfg["session_dir"] / "build" / "host_network_snapshot.json"
                snap.parent.mkdir(parents=True, exist_ok=True)
                res = repair_usb_network_via_worker(
                    run_host_net_fn=lambda sub: self._run_subprocess_streaming(
                        build_worker_command("--run-host-network", cfg["kit_root"], sub), cfg=cfg, timeout_sec=90.0
                    ),
                    snapshot_path=snap,
                )
                if not res.get("ok"):
                    raise RuntimeError(str(res.get("error") or "USB 网卡修复未通过核验"))
                self.log_from_worker(f"[OK] {res.get('message') or 'USB 网卡修复并完成防断网隔离复核。'}", "OK")
                self._post_ui("call", self._trigger_radar_now)

            self._launch_bg_task("正在扫描并修复 USB 网卡...", task)

        def _action_restore_host_net(self) -> None:
            session_dir = Path(self.session_dir_var.get())
            snap = session_dir / "build" / "host_network_snapshot.json"
            if not snap.is_file():
                messagebox.showinfo("未找到快照", f"未找到本次会话的网卡隔离快照：{snap}")
                return
            if not self.last_usb_state.get("query_ok", False) or self.last_usb_state.get("present_modes") or self.last_usb_state.get("state") != "disconnected":
                messagebox.showwarning(
                    "请先彻底拔掉 F50 Pro USB 线",
                    "安全拦截（fail-closed）：当前检测到 F50 Pro USB 设备仍在线（或 PnP 状态未确认）。\n"
                    "此时恢复原网卡 DHCP/网关/IPv6 快照可能导致宿主机默认路由泄露或断网，请先物理拔掉 USB 线、确认顶部雷达显示「未检测到 F50 Pro 设备」后再恢复。",
                )
                return

            def task(cfg: dict[str, Any]) -> None:
                live = detect_usb_device_state(probe_network=False)
                if not live.get("query_ok") or live.get("present_modes") or live.get("state") != "disconnected":
                    raise RuntimeError("安全拦截：F50 Pro USB 设备仍在线或 PnP 查询失败，拒绝恢复网卡快照。")
                rc, out = self._run_subprocess_streaming(
                    build_worker_command("--run-host-network", cfg["kit_root"], ["restore", "--snapshot", str(snap)]),
                    cfg=cfg,
                    timeout_sec=90.0,
                )
                rest_json = extract_last_json_object(out) or {}
                if rc != 0 or not rest_json.get("all_restored"):
                    raise RuntimeError(f"恢复快照未全部生效（exit={rc}, restored={rest_json.get('restored_count', 0)}, skipped={rest_json.get('skipped_count', 0)}）：\n{out[-800:]}")
                self.log_from_worker("[OK] 已安全恢复隔离前的原网卡配置快照。", "OK")

            self._launch_bg_task("正在恢复隔离前原网卡快照...", task)

        def _action_rollback_a(self) -> None:
            if not self._validate_common_form():
                return
            session_dir = Path(self.session_dir_var.get())
            plan_path = session_dir / "build" / "flash_plan.json"
            if not plan_path.is_file():
                messagebox.showwarning("缺少已校验计划", f"未找到 {plan_path}（受控回退必须绑定本机备份与 flash_plan.json 身份指纹）。")
                return

            def dry_run_task(cfg: dict[str, Any]) -> dict[str, Any]:
                rc_d, out_d = self._run_subprocess_streaming(
                    build_worker_command(
                        "--run-kit",
                        cfg["kit_root"],
                        ["rollback-a", "--plan", str(plan_path), "--tools-dir", str(cfg["tools_dir"])],
                    ),
                    cfg=cfg,
                    timeout_sec=120.0,
                )
                if rc_d != 0:
                    raise RuntimeError(f"受控回退干跑校验未通过（exit={rc_d}）：\n{out_d[-1200:]}")
                info = extract_last_json_object(out_d) or {}
                if len(str(info.get("plan_sha256") or "")) != 64 or len(str(info.get("rollback_sha256") or "")) != 64:
                    raise RuntimeError("受控回退干跑结果缺少有效 plan_sha256 / rollback_sha256 摘要。")
                return info

            def ask_user_after_idle(info: dict[str, Any]) -> None:
                p_sha = str(info["plan_sha256"])
                r_sha = str(info["rollback_sha256"])
                ok = messagebox.askyesno(
                    "确认执行受控切回原厂安卓 (_a)",
                    f"已通过受控回退干跑校验：\n\n"
                    f"• 目标分区：misc 偏移 2048（仅 32 字节 BCAB，目标槽位 _a）\n"
                    f"• 本机设备指纹：{str(info.get('unit_identity_sha256') or '')[:16]}...\n"
                    f"• 计划摘要 (plan_sha256)：{p_sha[:16]}...\n"
                    f"• 回退块摘要 (rollback_sha256)：{r_sha[:16]}...\n\n"
                    f"执行时会严格绑定上述摘要，在同一 SPRD4 会话内重新核验 GPT、本机身份、写前槽位状态与写后读回 SHA-256，校验通过才发送重启。\n"
                    f"期间窗口将锁定，切勿拔线。确认执行吗？",
                    icon="warning",
                )
                if ok:
                    self._execute_controlled_rollback(plan_path, expected_plan_sha=p_sha, expected_rollback_sha=r_sha)

            self._launch_bg_task("正在执行受控回退干跑校验...", dry_run_task, on_success=ask_user_after_idle)

        def _execute_controlled_rollback(
            self,
            plan_path: Path,
            *,
            expected_plan_sha: str,
            expected_rollback_sha: str,
        ) -> None:
            if not self._check_reconcile_write_intent(plan_path.parents[1]):
                return

            def task(cfg: dict[str, Any]) -> None:
                args = [
                    "rollback-a",
                    "--plan",
                    str(plan_path),
                    "--tools-dir",
                    str(cfg["tools_dir"]),
                    "--expected-plan-sha256",
                    expected_plan_sha,
                    "--expected-rollback-sha256",
                    expected_rollback_sha,
                    "--secrets-stdin",
                    "--execute",
                ]
                secrets_payload: dict[str, str] = {}
                if cfg["webui_pw"] != "":
                    secrets_payload["webui_password"] = cfg["webui_pw"]

                rb_run_dir = plan_path.parent / "rollback-run"
                rb_run_dir.mkdir(parents=True, exist_ok=True)
                fr = rb_run_dir / "rollback_failure_report.json"
                if fr.is_file():
                    try:
                        fr.replace(rb_run_dir / "rollback_failure_report.prev.json")
                    except OSError:
                        fr.unlink(missing_ok=True)
                intent_path = rb_run_dir / "active_write_intent.json"
                attempt_id = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + "-" + _secrets.token_hex(4)
                intent_path.write_text(
                    json.dumps({"attempt_id": attempt_id, "operation": "rollback_a", "plan_sha256": expected_plan_sha, "rollback_sha256": expected_rollback_sha, "state": "in_progress"}, indent=2) + "\n",
                    encoding="utf-8",
                )

                # NEVER attach a blind GUI kill-timer to an active flash/rollback write!
                rc, out = self._run_subprocess_streaming(
                    build_worker_command("--run-kit", cfg["kit_root"], args),
                    cfg=cfg,
                    stdin_secrets=secrets_payload,
                    timeout_sec=None,
                )
                parsed = extract_last_json_object(out) or {}
                if rc != 0 or parsed.get("status") != "ROLLBACK_A_VERIFIED" or parsed.get("reset_sent") is not True:
                    fail_rep = None
                    if fr.is_file():
                        try:
                            fail_rep = json.loads(fr.read_text(encoding="utf-8"))
                        except Exception:
                            pass
                    intent_path.write_text(
                        json.dumps({"attempt_id": attempt_id, "operation": "rollback_a", "state": "failed_reconcile_required", "rc": rc, "status": parsed.get("status"), "reset_sent": parsed.get("reset_sent")}, indent=2) + "\n",
                        encoding="utf-8",
                    )
                    diag = diagnose_failure(out, failure_report=fail_rep)
                    raise _DiagnosedTaskError(
                        f"受控回退未完成或重启指令未确认（exit={rc}, status={parsed.get('status')}, reset_sent={parsed.get('reset_sent')}）：{diag['title']}",
                        diag,
                    )
                intent_path.unlink(missing_ok=True)
                self.log_from_worker("[OK] 已完成身份、写前槽位与读回校验并发送重启指令，请等待约 25 秒确认顶部雷达变为原厂安卓 (19D2:0246)。", "OK")
                self._post_ui(
                    "call",
                    lambda: messagebox.showinfo(
                        "受控回退指令已发送",
                        "已通过全部身份、写前状态与读回校验，并已确认发送重启指令（reset_sent=true）。\n"
                        "请等待约 25 秒，待顶部 USB 雷达显示「原厂安卓 (19D2:0246)」且可打开 http://192.168.0.1:8080 即确认成功启动回原厂安卓。",
                    ),
                )

            self._launch_bg_task("正在执行受控切回原厂安卓（窗口已锁定，切勿拔线）...", task, is_flash=True)

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
            cfg = self._snapshot_config()
            log_snapshot = "\n".join(self.full_log_lines[-200:])
            diag_snap = dict(self.last_diag) if isinstance(self.last_diag, dict) else None

            def worker() -> None:
                try:
                    report = build_sanitized_diagnostic_report(
                        kit_version=cfg["kit_version"],
                        workspace_dir=cfg["session_dir"],
                        log_tail=log_snapshot,
                        secrets=cfg["secrets"],
                        last_diag=diag_snap,
                    )
                    Path(out_path).write_text(report, encoding="utf-8")
                    self.log_from_worker("[OK] 已导出脱敏诊断报告（仅含白名单字段与结构化事件）。", "OK")
                    self._post_ui("call", lambda: messagebox.showinfo("导出成功", f"脱敏诊断报告已保存：\n{out_path}\n仅含白名单诊断字段与结构化事件，可直接用于排查。"))
                except Exception as exc:
                    self.log_from_worker(f"[ERR] 导出脱敏诊断报告失败：{exc}", "ERR", secrets=cfg["secrets"])
                    self._post_ui("call", lambda err=str(exc): messagebox.showerror("导出脱敏诊断报告失败", err))

            threading.Thread(target=worker, daemon=True).start()

        def _on_close(self) -> None:
            if self.active_is_flash:
                messagebox.showerror(
                    "禁止关闭窗口",
                    "当前正处于闪存写入/读回校验关键阶段，严禁强行关闭窗口或拔掉 USB 线！\n请等待本阶段完成或自动安全暂停后再关闭。",
                )
                return
            if self.busy:
                if not messagebox.askyesno("任务仍在运行", "当前有非写入任务正在执行，关闭窗口将终止它。确定退出吗？"):
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
        try:
            return _dispatch_embedded_script(args[0], args)
        except BaseException as exc:
            _ensure_worker_streams()
            _emit_worker_error(type(exc).__name__, str(exc))
            return 1
    if args and args[0] == "--smoke-gui":
        try:
            _ensure_worker_streams()
            return launch_gui(smoke_test=True)
        except BaseException as exc:
            _emit_worker_error(type(exc).__name__, str(exc))
            return 1
    return launch_gui(smoke_test=False)


if __name__ == "__main__":
    raise SystemExit(main())
