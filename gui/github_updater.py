"""GitHub Release auto-updater with HTTPS mirror fallback and strict SHA-256 verification."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tarfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

GITHUB_REPO = "tanjiu90/f50pro-dualboot-kit"
GITHUB_API_LATEST = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
GITHUB_LATEST_PAGE = f"https://github.com/{GITHUB_REPO}/releases/latest"

PRESET_MIRRORS: tuple[tuple[str, str], ...] = (
    ("直连 GitHub (推荐有代理/海外)", ""),
    ("国内镜像 1 (ghfast.top)", "https://ghfast.top/"),
    ("国内镜像 2 (gh-proxy.com)", "https://gh-proxy.com/"),
    ("仅离线本地模式 (不联网)", "__OFFLINE__"),
)

_TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9._-]+)?$")
_SHA_LINE_RE = re.compile(r"^([0-9a-fA-F]{64})\s+\*?(\S+)$")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def normalize_mirror_prefix(mirror: str) -> str:
    """Validate and normalize an optional HTTPS GitHub mirror prefix."""
    m = (mirror or "").strip()
    if not m or m == "__OFFLINE__":
        return m
    if not m.startswith("https://"):
        raise ValueError(f"镜像地址必须以 https:// 开头：{m}")
    return m.rstrip("/") + "/"


def build_candidate_urls(url: str, mirror_prefix: str = "") -> list[str]:
    """Return ordered HTTPS download URLs with optional mirror first and direct GitHub fallback."""
    m = normalize_mirror_prefix(mirror_prefix)
    if m and m != "__OFFLINE__" and url.startswith("https://github.com/"):
        return [f"{m}{url}", url]
    return [url]


def _http_get_bytes(
    url: str,
    *,
    timeout: float = 30.0,
    accept: str = "*/*",
    progress_cb: Callable[[int, int], None] | None = None,
) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "f50pro-dualboot-kit-gui/1.1.2",
            "Accept": accept,
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        total = int(resp.headers.get("Content-Length") or 0)
        chunks: list[bytes] = []
        done = 0
        while True:
            buf = resp.read(1 << 18)
            if not buf:
                break
            chunks.append(buf)
            done += len(buf)
            if progress_cb:
                progress_cb(done, total)
        return b"".join(chunks)


def parse_sha256sums(text: str) -> dict[str, str]:
    """Parse standard `SHA256SUMS.txt` into `{filename: lowercase_sha256}`."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _SHA_LINE_RE.match(line)
        if m:
            out[Path(m.group(2)).name] = m.group(1).lower()
    return out


def fetch_latest_release_info(
    *,
    repo: str = GITHUB_REPO,
    mirror_prefix: str = "",
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Query GitHub latest release metadata (API first, redirect tag fallback via mirror if API is blocked)."""
    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        raw = _http_get_bytes(api_url, timeout=timeout, accept="application/vnd.github+json")
        data = json.loads(raw.decode("utf-8"))
        tag = str(data.get("tag_name") or "").strip()
        if not _TAG_RE.match(tag):
            raise ValueError(f"Unexpected release tag from GitHub API: {tag!r}")
        assets: dict[str, dict[str, Any]] = {}
        for item in data.get("assets") or []:
            name = str(item.get("name") or "")
            if name:
                assets[name] = {
                    "name": name,
                    "size": int(item.get("size") or 0),
                    "url": str(item.get("browser_download_url") or ""),
                }
        return {
            "source": "github_api",
            "tag": tag,
            "name": str(data.get("name") or tag),
            "published_at": str(data.get("published_at") or ""),
            "html_url": str(data.get("html_url") or f"https://github.com/{repo}/releases/tag/{tag}"),
            "assets": assets,
        }
    except Exception as api_exc:
        # Fallback: follow releases/latest HTML redirect (works through GitHub mirror when api.github.com is rate-limited/blocked)
        latest_url = f"https://github.com/{repo}/releases/latest"
        last_exc: Exception = api_exc
        for cand in build_candidate_urls(latest_url, mirror_prefix):
            try:
                req = urllib.request.Request(cand, headers={"User-Agent": "f50pro-dualboot-kit-gui/1.1.2"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    final_url = resp.geturl()
                m = re.search(r"/releases/tag/(v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9._-]+)?)", final_url)
                if not m:
                    raise ValueError(f"Could not extract release tag from redirect URL: {final_url}")
                tag = m.group(1)
                base_dl = f"https://github.com/{repo}/releases/download/{tag}"
                src_name = f"f50pro-dualboot-kit-{tag}-src.tar.gz"
                return {
                    "source": "redirect_fallback",
                    "tag": tag,
                    "name": f"Release {tag}",
                    "published_at": "",
                    "html_url": f"https://github.com/{repo}/releases/tag/{tag}",
                    "assets": {
                        src_name: {"name": src_name, "size": 0, "url": f"{base_dl}/{src_name}"},
                        "SHA256SUMS.txt": {"name": "SHA256SUMS.txt", "size": 0, "url": f"{base_dl}/SHA256SUMS.txt"},
                    },
                }
            except Exception as exc:
                last_exc = exc
        raise RuntimeError(f"无法连接 GitHub 获取最新版本（可切换国内镜像或使用离线内置版）：{last_exc}") from last_exc


def _safe_extract_tar_gz(archive: Path, dst_dir: Path) -> Path:
    """Safely extract release source tarball (blocking traversal, symlinks outside root, and special nodes)."""
    if dst_dir.exists():
        shutil.rmtree(dst_dir)
    dst_dir.mkdir(parents=True, exist_ok=True)
    root = dst_dir.resolve()
    top_dirs: set[str] = set()
    with tarfile.open(archive, "r:gz") as tf:
        for member in tf.getmembers():
            if member.isdev() or member.isfifo() or not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise ValueError(f"Refusing unsupported tar entry: {member.name}")
            if Path(member.name).is_absolute():
                raise ValueError(f"Refusing absolute tar path: {member.name}")
            dest = (root / member.name).resolve()
            dest.relative_to(root)
            if member.issym():
                (dest.parent / member.linkname).resolve().relative_to(root)
            elif member.islnk():
                (root / member.linkname).resolve().relative_to(root)
            parts = Path(member.name).parts
            if parts:
                top_dirs.add(parts[0])
            member.mode &= 0o777
            try:
                tf.extract(member, root, filter="data")
            except TypeError:
                tf.extract(member, root)

    if len(top_dirs) == 1:
        nested = root / next(iter(top_dirs))
        if nested.is_dir() and (nested / "scripts" / "kit.py").is_file():
            return nested
    if (root / "scripts" / "kit.py").is_file():
        return root
    raise RuntimeError(f"解压后的源码包缺少 scripts/kit.py：{root}")


def download_and_verify_kit_release(
    release_info: dict[str, Any],
    *,
    kit_store_dir: Path,
    mirror_prefix: str = "",
    log_cb: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Download latest source tarball + SHA256SUMS.txt from GitHub, verify SHA-256, and extract cleanly."""
    tag = str(release_info["tag"])
    if not _TAG_RE.match(tag):
        raise ValueError(f"Invalid release tag: {tag!r}")

    target_wrap = kit_store_dir / tag
    marker = target_wrap / ".kit_verified.json"
    if marker.is_file():
        try:
            cached = json.loads(marker.read_text(encoding="utf-8"))
            cached_root = Path(cached["kit_root"])
            if (cached_root / "scripts" / "kit.py").is_file() and (cached_root / "assets" / "release-manifest.json").is_file():
                if log_cb:
                    log_cb(f"[OK] 本地已缓存并校验过 {tag} 刷机脚本，直接使用。")
                return {
                    "status": "cached",
                    "tag": tag,
                    "kit_root": cached_root,
                    "src_sha256": cached.get("src_sha256", ""),
                }
        except Exception:
            pass

    assets = release_info.get("assets") or {}
    src_name = f"f50pro-dualboot-kit-{tag}-src.tar.gz"
    if src_name not in assets or "SHA256SUMS.txt" not in assets:
        raise RuntimeError(f"Release {tag} 缺少 {src_name} 或 SHA256SUMS.txt，拒绝未校验拉取。")

    sums_url = assets["SHA256SUMS.txt"]["url"]
    src_url = assets[src_name]["url"]

    sums_bytes: bytes | None = None
    last_err: Exception | None = None
    for cand in build_candidate_urls(sums_url, mirror_prefix):
        if log_cb:
            log_cb(f"下载校验清单：{cand}")
        try:
            sums_bytes = _http_get_bytes(cand, timeout=30.0)
            break
        except Exception as exc:
            last_err = exc
            if log_cb:
                log_cb(f"[WARN] 校验清单下载失败（尝试备用地址）：{exc}")
    if sums_bytes is None:
        raise RuntimeError(f"无法下载 SHA256SUMS.txt：{last_err}")

    sums = parse_sha256sums(sums_bytes.decode("utf-8", errors="replace"))
    expected_sha = sums.get(src_name)
    if not expected_sha:
        raise RuntimeError(f"SHA256SUMS.txt 中未包含 {src_name} 的校验值，出于安全原因拒绝安装。")

    kit_store_dir.mkdir(parents=True, exist_ok=True)
    archive_path = kit_store_dir / f"{src_name}.part"
    verified = False
    for cand in build_candidate_urls(src_url, mirror_prefix):
        if log_cb:
            log_cb(f"下载 {tag} 刷机工具源码包：{cand}")
        try:
            data = _http_get_bytes(cand, timeout=90.0)
            archive_path.write_bytes(data)
            actual_sha = sha256_file(archive_path)
            if actual_sha != expected_sha:
                archive_path.unlink(missing_ok=True)
                raise ValueError(f"SHA-256 校验不匹配（可能镜像缓存异常）：{actual_sha[:16]} != {expected_sha[:16]}")
            verified = True
            break
        except Exception as exc:
            last_err = exc
            archive_path.unlink(missing_ok=True)
            if log_cb:
                log_cb(f"[WARN] 源码包拉取/校验失败（尝试备用地址）：{exc}")
    if not verified:
        raise RuntimeError(f"无法获取通过 SHA-256 校验的 {src_name}：{last_err}")

    final_archive = kit_store_dir / src_name
    archive_path.replace(final_archive)

    if log_cb:
        log_cb(f"[OK] {src_name} SHA-256 校验通过（{expected_sha[:12]}...），正在解压...")
    kit_root = _safe_extract_tar_gz(final_archive, target_wrap)
    if not (kit_root / "assets" / "release-manifest.json").is_file():
        raise RuntimeError(f"解压后的 {tag} 缺少 assets/release-manifest.json")

    marker.write_text(
        json.dumps({"tag": tag, "kit_root": str(kit_root), "src_sha256": expected_sha}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return {
        "status": "downloaded",
        "tag": tag,
        "kit_root": kit_root,
        "src_sha256": expected_sha,
    }


def resolve_kit_version(kit_root: Path) -> str:
    """Read human-friendly version label from a local or cached kit directory."""
    parent_marker = kit_root.parent / ".kit_verified.json"
    if parent_marker.is_file():
        try:
            return str(json.loads(parent_marker.read_text(encoding="utf-8")).get("tag") or "local")
        except Exception:
            pass
    guide = kit_root / "docs" / "beginner-guide.md"
    if guide.is_file():
        m = re.search(r"f50pro-dualboot-kit\s+(v[0-9]+\.[0-9]+\.[0-9]+)", guide.read_text(encoding="utf-8", errors="ignore"))
        if m:
            return m.group(1)
    return "bundled"
