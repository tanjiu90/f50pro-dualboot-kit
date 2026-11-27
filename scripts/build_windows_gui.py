"""Reproducible PyInstaller --onedir build script for portable F50Pro-Flasher-win64.zip."""
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Explicitly include every stdlib & third-party module needed when running downloaded kit.py via --run-kit.
HIDDEN_IMPORTS: tuple[str, ...] = (
    "paramiko",
    "serial",
    "serial.tools",
    "serial.tools.list_ports",
    "cryptography",
    "bcrypt",
    "nacl",
    "sqlite3",
    "lzma",
    "zlib",
    "xml.etree.ElementTree",
    "http.client",
    "http.cookiejar",
    "urllib.request",
    "urllib.parse",
    "urllib.error",
    "runpy",
    "shlex",
    "secrets",
    "uuid",
    "hmac",
    "ipaddress",
    "tarfile",
    "zipfile",
    "ctypes",
    "ctypes.wintypes",
    "concurrent.futures",
    "queue",
    "socket",
)

QUICKSTART_TXT = """============================================================
  中兴 F50 Pro (MU3356) 一键双系统刷机助手 (Windows 绿色版)
============================================================

【使用前必看 3 条】
1. 请务必先把整个压缩包完整解压到普通文件夹（例如 D:\\F50Pro-Flasher），
   不要直接在压缩软件里双击运行，也不要放到带空格或深层桌面路径。
2. 双击 F50Pro-Flasher.exe 启动（系统弹出 UAC 管理员确认框时请点「是」）。
3. 仅支持中兴 F50 Pro（型号 MU3356，含插卡版 B28 / 内置双 eSIM 版 B15），
   严禁用于普通 F50 (MU300)、U30 Air 或 U30 Pro。

【极简 3 步】
1. 在「① 环境体检与自动拉取」点击「一键拉取 GitHub 最新版并完成全部体检」
   - 如国内下载慢，可在顶部把「下载线路」切换为国内镜像 1 / 2；
   - 程序会自动下载校验最新版刷机脚本与固件包，并自动以 --force --all
     预装展锐 WinUSB 驱动（彻底告别 No matching device found）。
2. 在「② 方案与密码设置」选好方案（推荐方案 3 双系统全功能），输入原厂
   后台密码（机身背面贴纸）并点「立即验证密码」。
3. 在「③ 备份、预览与一键刷机」先点「① 只读备份原厂分区」，再点
   「③ 开始一键刷入」，等待 5~10 分钟即可（期间切勿拔线或断电）。

如遇任何报错，程序底部会自动弹出「自动排查诊断」和「一键修复」按钮，
也可点击「导出脱敏诊断报告」发群排查（会自动隐藏密码与隐私信息）。
"""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def build_portable_gui(*, output_zip: Path, uac_admin: bool = True) -> dict[str, object]:
    if sys.platform != "win32":
        raise RuntimeError("F50Pro-Flasher-win64.zip must be built on Windows.")

    pyinstaller_cmd = [sys.executable, "-m", "PyInstaller"]
    chk = subprocess.run([*pyinstaller_cmd, "--version"], capture_output=True, text=True)
    if chk.returncode != 0:
        exe = shutil.which("pyinstaller")
        if not exe:
            raise RuntimeError(
                "PyInstaller not found in active Python environment. "
                "Install with: python -m pip install pyinstaller"
            )
        pyinstaller_cmd = [exe]

    work_build = REPO_ROOT / "build" / "pyinstaller-gui"
    dist_stage = REPO_ROOT / "build" / "pyinstaller-dist"
    spec_dir = REPO_ROOT / "build" / "pyinstaller-spec"
    for d in (work_build, dist_stage, spec_dir):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)

    # Filter out scripts/__pycache__ before staging clean add-data copies
    clean_data = work_build / "staged-data"
    shutil.copytree(
        REPO_ROOT / "scripts",
        clean_data / "scripts",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "build_windows_gui.py"),
    )
    shutil.copytree(REPO_ROOT / "assets", clean_data / "assets")
    (clean_data / "docs").mkdir(parents=True, exist_ok=True)
    shutil.copy2(REPO_ROOT / "docs" / "beginner-guide.md", clean_data / "docs" / "beginner-guide.md")

    cmd: list[str] = [
        *pyinstaller_cmd,
        "--noconfirm",
        "--clean",
        "--onedir",
        "--windowed",
        "--name",
        "F50Pro-Flasher",
        "--distpath",
        str(dist_stage),
        "--workpath",
        str(work_build / "work"),
        "--specpath",
        str(spec_dir),
        "--add-data",
        f"{clean_data / 'scripts'};scripts",
        "--add-data",
        f"{clean_data / 'assets'};assets",
        "--add-data",
        f"{clean_data / 'docs'};docs",
        "--collect-submodules",
        "paramiko",
        "--collect-submodules",
        "serial",
    ]
    if uac_admin:
        cmd.append("--uac-admin")
    for mod in HIDDEN_IMPORTS:
        cmd += ["--hidden-import", mod]
    cmd.append(str(REPO_ROOT / "gui" / "flasher_app.py"))

    print("Running:", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True, cwd=str(REPO_ROOT))

    app_dir = dist_stage / "F50Pro-Flasher"
    exe_path = app_dir / "F50Pro-Flasher.exe"
    if not exe_path.is_file():
        raise RuntimeError(f"Expected built executable missing: {exe_path}")

    (app_dir / "使用说明-请先解压再双击运行.txt").write_text(QUICKSTART_TXT, encoding="utf-8")

    output_zip.parent.mkdir(parents=True, exist_ok=True)
    if output_zip.exists():
        output_zip.unlink()
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for item in sorted(app_dir.rglob("*")):
            if item.is_file():
                arcname = Path("F50Pro-Flasher") / item.relative_to(app_dir)
                zf.write(item, arcname.as_posix())

    digest = sha256_file(output_zip)
    size = output_zip.stat().st_size
    print(f"Built portable archive: {output_zip} ({size / (1024 * 1024):.2f} MiB, sha256={digest})")
    return {
        "exe": str(exe_path),
        "zip": str(output_zip),
        "bytes": size,
        "sha256": digest,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-zip",
        type=Path,
        default=REPO_ROOT / "dist" / "F50Pro-Flasher-win64.zip",
    )
    parser.add_argument("--no-uac-admin", action="store_true", help="Disable UAC admin manifest (e.g. for non-admin smoke tests)")
    args = parser.parse_args()
    build_portable_gui(output_zip=args.output_zip, uac_admin=not args.no_uac_admin)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
