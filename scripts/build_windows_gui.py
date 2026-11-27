"""Reproducible PyInstaller --onedir build script for portable F50Pro-Flasher-win64.zip (clean-commit, sanitization & ZIP audit gates)."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Explicitly include every stdlib & third-party module needed when running kit.py via --run-kit.
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

SANITIZE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key_header", re.compile(r"BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|PRIVATE) KEY")),
    ("github_or_cloud_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{10,}\b|\b(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{20,})\b")),
    ("ssh_public_key_material", re.compile(r"\b(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256)\s+[A-Za-z0-9+/=]{32,}")),
    ("raw_imei_15_digits", re.compile(r"(?<![0-9a-fA-F])86\d{13}(?![0-9a-fA-F])")),
    ("raw_iccid_or_imsi", re.compile(r"(?<![0-9a-fA-F])(?:8986\d{14,16}|460\d{12})(?![0-9a-fA-F])")),
    ("proxy_subscription_uri", re.compile(r"\b(?:vmess|vless|trojan|ssr|hysteria2?|tuic)://[^\s\"'<>`]+", re.I)),
    ("local_windows_user_path", re.compile(r"[A-Za-z]:[/\\]+Users[/\\]+(?!(?:Public|Default|runneradmin)\b|<)[A-Za-z0-9._-]+", re.I)),
    ("local_unix_user_path", re.compile(r"(?:/Users|/home)/(?!(?:runner|ubuntu|user|admin)\b|<)[a-z_][a-z0-9._-]*(?=/|$)")),
)

FORBIDDEN_BUNDLE_FILENAMES: frozenset[str] = frozenset(
    {
        "prodnv",
        "calinv",
        "miscdata",
        "persist",
        "partition_list.xml",
        "openwrt-credentials.json",
        "android-ttyd-credentials.json",
        "adbkey",
        "adbkey.pub",
    }
)

FORBIDDEN_PERSONAL_POLICY_TOKENS: tuple[str, ...] = ("25.12.6", "theme-f50v3", "vowifi")

QUICKSTART_TXT = """============================================================
  中兴 F50 Pro (MU3356) 一键双系统刷机助手 (Windows 绿色版)
============================================================

【使用前必看 3 条】
1. 请务必先把整个压缩包完整解压到纯英文简短路径（例如 D:\\F50Pro-Flasher），
   不要直接在压缩软件里双击运行，避免中文或编码问题影响底层驱动/刷机工具。
2. 双击 F50Pro-Flasher.exe 启动（系统弹出 UAC 管理员确认框时请点「是」）。
3. 仅支持中兴 F50 Pro（型号 MU3356，含插卡版 B28 / 内置双 eSIM 版 B15），
   严禁用于普通 F50 (MU300)、U30 Air 或 U30 Pro。

【稳妥 3 步】
1. 在「① 环境体检与自动拉取」点击「一键拉取并完成全部体检」
   - 刷机脚本摘要严格直连官方 GitHub 校验并核验协议兼容与 25.12.5 公共策略；
   - 大体积固件包支持通过国内 HTTPS 加速镜像下载，并强制与内置官方清单 SHA-256 核对；
   - 驱动安装前先绑定校验官方 zip 内的 qmk_driver_installer.exe 哈希，再以 --force --all
     预装并核验 1782:4D00 与 1782:4D03 均已入库且无实机冲突绑定。
2. 在「② 方案与密码设置」选好方案（推荐方案 3 双系统全功能），输入原厂
   后台密码（机身背面贴纸）并点「立即验证密码」；默认自动生成本机唯一高强度
   OpenWrt root 密码与 Wi-Fi 密码（刷完保存在本机凭据文件）。
3. 在「③ 备份、预览与一键刷机」依次执行：
   ① 只读备份原厂分区 -> ② 生成离线干跑预览（核对设备指纹、写入清单与计划哈希） -> ③ 正式刷入。
   刷写期间窗口会自动锁定防止误关，严禁拔线或断电。

如遇报错，底部会自动弹出「自动排查诊断」与「一键修复」按钮，也可点击
「导出脱敏诊断报告」发群排查（仅导出白名单字段与结构化事件，自动隐藏密码、设备标识与路径）。
"""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def _git_working_tree_dirty(repo_root: Path) -> list[str]:
    res = subprocess.run(
        ["git", "-C", str(repo_root), "status", "--porcelain", "--untracked-files=no"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return [ln for ln in res.stdout.splitlines() if ln.strip()]


def _list_tracked_bundle_files(repo_root: Path) -> list[Path]:
    """Return ONLY git-tracked files under scripts/, assets/, and docs/beginner-guide.md (never untracked local files)."""
    res = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z", "--", "scripts", "assets", "docs/beginner-guide.md"],
        capture_output=True,
        check=True,
    )
    out: list[Path] = []
    for raw in res.stdout.split(b"\x00"):
        if not raw:
            continue
        rel = raw.decode("utf-8")
        if rel == "scripts/build_windows_gui.py":
            continue
        p = repo_root / rel
        if p.is_file():
            out.append(Path(rel))
    if not out:
        raise RuntimeError("No git-tracked files found to bundle under scripts/ and assets/.")
    return sorted(out)


def _scan_bytes_sanitization(rel_label: str, raw: bytes) -> list[str]:
    violations: list[str] = []
    fname = Path(rel_label).name.lower()
    if fname in FORBIDDEN_BUNDLE_FILENAMES or fname.endswith((".pem", ".key")):
        violations.append(f"{rel_label}: forbidden raw backup or secret filename")
    try:
        txt = raw.decode("utf-8")
    except UnicodeDecodeError:
        txt = raw.decode("latin-1", errors="ignore")
    for label, pat in SANITIZE_PATTERNS:
        if pat.search(txt):
            violations.append(f"{rel_label}: matched {label}")
    low = txt.lower()
    norm_rel = rel_label.replace("\\", "/")
    is_policy_checker_or_test = (
        norm_rel.endswith("github_updater.py")
        or norm_rel.endswith("build_windows_gui.py")
        or "/tests/" in f"/{norm_rel}"
    )
    if not is_policy_checker_or_test:
        for bad in FORBIDDEN_PERSONAL_POLICY_TOKENS:
            if bad in low:
                violations.append(f"{rel_label}: matched forbidden personal customization token {bad!r}")
    return violations


def _audit_staged_tree_sanitization(staged_root: Path) -> None:
    violations: list[str] = []
    for p in sorted(staged_root.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(staged_root).as_posix()
        violations.extend(_scan_bytes_sanitization(rel, p.read_bytes()))
    if violations:
        raise RuntimeError(f"Refusing to package GUI due to sanitization/policy violations: {violations}")


def _audit_finished_zip(output_zip: Path) -> dict[str, object]:
    """Verify completed ZIP CRC integrity, required payload paths, public 25.12.5 manifest, and text sanitization."""
    with zipfile.ZipFile(output_zip, "r") as zf:
        bad_member = zf.testzip()
        if bad_member is not None:
            raise RuntimeError(f"ZIP CRC verification failed on member: {bad_member}")
        names = set(zf.namelist())
        required = (
            "F50Pro-Flasher/F50Pro-Flasher.exe",
            "F50Pro-Flasher/_internal/scripts/kit.py",
            "F50Pro-Flasher/_internal/scripts/build_images.py",
            "F50Pro-Flasher/_internal/assets/release-manifest.json",
            "F50Pro-Flasher/_internal/docs/beginner-guide.md",
        )
        missing = [r for r in required if r not in names]
        if missing:
            raise RuntimeError(f"Finished ZIP missing required members: {missing}")

        build_py = zf.read("F50Pro-Flasher/_internal/scripts/build_images.py").decode("utf-8")
        if "openwrt-f50pro-25.12.5-base-rootfs.ext4" not in build_py:
            raise RuntimeError("Finished ZIP build_images.py does not pin public OpenWrt 25.12.5")

        violations: list[str] = []
        text_exts = {".py", ".sh", ".rpcd", ".js", ".json", ".md", ".txt", ".bat", ".ps1", ".yaml", ".yml", ".rules", ".rc", ".tpl", ".cfg", ".conf"}
        for member in sorted(names):
            low_m = member.lower()
            if (
                member.startswith("F50Pro-Flasher/_internal/scripts/")
                or member.startswith("F50Pro-Flasher/_internal/assets/")
                or Path(low_m).suffix in text_exts
            ):
                violations.extend(_scan_bytes_sanitization(member, zf.read(member)))
        if violations:
            raise RuntimeError(f"Finished ZIP failed post-build sanitization audit: {violations}")
        return {"member_count": len(names), "crc_ok": True, "sanitization_ok": True}


def audit_source_tarball(tar_path: Path) -> dict[str, object]:
    """Audit a release source tarball for sanitization, raw-backup absence, and public OpenWrt 25.12.5 policy."""
    import tarfile

    violations: list[str] = []
    seen_build = False
    count = 0
    with tarfile.open(tar_path, "r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            count += 1
            fh = tf.extractfile(member)
            if fh is None:
                continue
            data = fh.read()
            if member.name.endswith("scripts/build_images.py"):
                seen_build = True
                if b"openwrt-f50pro-25.12.5-base-rootfs.ext4" not in data:
                    violations.append(f"{member.name}: missing pinned public OpenWrt 25.12.5 rootfs")
            violations.extend(_scan_bytes_sanitization(member.name, data))
    if not seen_build:
        violations.append("Source tarball missing scripts/build_images.py")
    if violations:
        raise RuntimeError(f"Source tarball failed sanitization/policy audit: {violations}")
    return {"tarball": tar_path.name, "file_count": count, "sha256": sha256_file(tar_path), "sanitization_ok": True}


def build_portable_gui(
    *,
    output_zip: Path,
    uac_admin: bool = True,
    allow_dirty: bool = False,
    metadata_out: Path | None = None,
) -> dict[str, object]:
    if sys.platform != "win32":
        raise RuntimeError("F50Pro-Flasher-win64.zip must be built on Windows.")

    dirty_files = _git_working_tree_dirty(REPO_ROOT)
    if dirty_files and not allow_dirty:
        raise RuntimeError(
            f"Refusing to build release artifact from dirty working tree ({len(dirty_files)} modified tracked files); "
            "commit changes first or pass --allow-dirty for local smoke builds only."
        )

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

    commit_sha = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()

    work_build = REPO_ROOT / "build" / "pyinstaller-gui"
    dist_stage = REPO_ROOT / "build" / "pyinstaller-dist"
    spec_dir = REPO_ROOT / "build" / "pyinstaller-spec"
    for d in (work_build, dist_stage, spec_dir):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)

    # Stage ONLY git-tracked files (directly from HEAD blob when clean!) and run mandatory PII/sanitization scan.
    clean_data = work_build / "staged-data"
    tracked_rels = _list_tracked_bundle_files(REPO_ROOT)
    for rel in tracked_rels:
        dst = clean_data / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not dirty_files:
            blob = subprocess.run(
                ["git", "-C", str(REPO_ROOT), "show", f"HEAD:{rel.as_posix()}"],
                capture_output=True,
                check=True,
            ).stdout
            dst.write_bytes(blob)
        else:
            shutil.copy2(REPO_ROOT / rel, dst)
    _audit_staged_tree_sanitization(clean_data)
    print(
        f"Staged {len(tracked_rels)} git-tracked files from commit {commit_sha[:12]} "
        f"(dirty={bool(dirty_files)}, sanitization PASS)",
        flush=True,
    )

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

    zip_audit = _audit_finished_zip(output_zip)
    digest = sha256_file(output_zip)
    size = output_zip.stat().st_size
    meta: dict[str, object] = {
        "commit": commit_sha,
        "dirty": bool(dirty_files),
        "uac_admin": uac_admin,
        "staged_file_count": len(tracked_rels),
        "zip_audit": zip_audit,
        "exe_name": exe_path.name,
        "zip_name": output_zip.name,
        "bytes": size,
        "sha256": digest,
    }
    if metadata_out is not None:
        metadata_out.parent.mkdir(parents=True, exist_ok=True)
        metadata_out.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(
        f"Built portable archive: {output_zip} ({size / (1024 * 1024):.2f} MiB, commit={commit_sha[:12]}, "
        f"dirty={bool(dirty_files)}, members={zip_audit['member_count']}, sha256={digest})"
    )
    return meta


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-zip",
        type=Path,
        default=REPO_ROOT / "dist" / "F50Pro-Flasher-win64.zip",
    )
    parser.add_argument("--no-uac-admin", action="store_true", help="Disable UAC admin manifest (e.g. for non-admin smoke tests)")
    parser.add_argument("--allow-dirty", action="store_true", help="Allow building from an uncommitted working tree (local smoke only)")
    parser.add_argument("--metadata-out", type=Path, help="Optional JSON file to record sanitized build provenance and SHA-256")
    parser.add_argument("--audit-tarball", type=Path, help="Audit an existing release source .tar.gz for sanitization & 25.12.5 policy and exit")
    args = parser.parse_args()
    if args.audit_tarball:
        res = audit_source_tarball(args.audit_tarball)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0
    build_portable_gui(
        output_zip=args.output_zip,
        uac_admin=not args.no_uac_admin,
        allow_dirty=args.allow_dirty,
        metadata_out=args.metadata_out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
