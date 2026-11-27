"""GitHub Release auto-updater with direct-GitHub trust anchor, protocol/policy gates, cross-process locking, and strict SHA-256 verification."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import tarfile
import threading
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable, Iterator

GITHUB_REPO = "tanjiu90/f50pro-dualboot-kit"
GITHUB_API_LATEST = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"

KIT_MIN_PROTOCOL_VERSION = 2
KIT_MAX_PROTOCOL_VERSION = 2
EXPECTED_OPENWRT_ROOTFS = "openwrt-f50pro-25.12.5-base-rootfs.ext4"
PINNED_PUBLIC_OPENWRT_BASE_SHA256 = "ebd302a22b3542057913d499390990f1ca1aeb87bd85d0b37024a77c2ba522b1"
FORBIDDEN_PERSONAL_MARKERS: tuple[str, ...] = ("25.12.6", "theme-f50v3", "vowifi")

PRESET_MIRRORS: tuple[tuple[str, str], ...] = (
    ("直连 GitHub (推荐有代理/海外)", ""),
    ("国内镜像 1 (ghfast.top，仅加速大包正文)", "https://ghfast.top/"),
    ("国内镜像 2 (gh-proxy.com，仅加速大包正文)", "https://gh-proxy.com/"),
    ("仅离线本地模式 (不联网)", "__OFFLINE__"),
)

_TAG_RE = re.compile(r"^v([0-9]+)\.([0-9]+)\.([0-9]+)(?:-[A-Za-z0-9._-]+)?$")
_SHA_LINE_RE = re.compile(r"^([0-9a-fA-F]{64})\s+\*?(\S+)$")
_DIGEST_RE = re.compile(r"^sha256:([0-9a-fA-F]{64})$", re.I)

MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_EXTRACTED_BYTES = 64 * 1024 * 1024
MAX_EXTRACTED_FILES = 2000
MAX_EXTRACTED_ENTRIES = 2500

_WIN_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(0, 10)}
    | {f"LPT{i}" for i in range(0, 10)}
)
_WIN_INVALID_CHARS = frozenset('<>:"|?*')

_TAG_LOCKS_GUARD = threading.Lock()
_TAG_LOCKS: dict[str, threading.Lock] = {}


def parse_semver(tag: str) -> tuple[int, int, int] | None:
    m = _TAG_RE.match((tag or "").strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def _get_tag_lock(tag: str) -> threading.Lock:
    with _TAG_LOCKS_GUARD:
        lock = _TAG_LOCKS.get(tag)
        if lock is None:
            lock = threading.Lock()
            _TAG_LOCKS[tag] = lock
        return lock


@contextlib.contextmanager
def _cross_process_tag_lock(kit_store_dir: Path, tag: str) -> Iterator[None]:
    """Serialize tag cache extraction/swap across both threads AND separate OS processes."""
    with _get_tag_lock(tag):
        kit_store_dir.mkdir(parents=True, exist_ok=True)
        lock_file = kit_store_dir / f".lock-{tag}"
        fh = lock_file.open("a+b")
        try:
            if os.name == "nt":
                import msvcrt

                fh.seek(0)
                if fh.tell() == 0 and lock_file.stat().st_size == 0:
                    fh.write(b"0")
                    fh.flush()
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            try:
                if os.name == "nt":
                    import msvcrt

                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            fh.close()


def _is_link_or_reparse(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
    return bool(attrs & reparse_flag)


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
    """Return ordered HTTPS download URLs for file content (mirror first, direct GitHub fallback)."""
    m = normalize_mirror_prefix(mirror_prefix)
    if m and m != "__OFFLINE__" and url.startswith("https://github.com/"):
        return [f"{m}{url}", url]
    return [url]


def _http_get_bytes(
    url: str,
    *,
    timeout: float = 30.0,
    accept: str = "*/*",
    max_bytes: int = MAX_ARCHIVE_BYTES,
    progress_cb: Callable[[int, int], None] | None = None,
) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "f50pro-dualboot-kit-gui/1.1.4",
            "Accept": accept,
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        cl_hdr = resp.headers.get("Content-Length")
        total = int(cl_hdr) if cl_hdr and cl_hdr.isdigit() else 0
        if total > max_bytes:
            raise ValueError(f"远端文件体积 ({total} B) 超过安全上限 ({max_bytes} B)")
        chunks: list[bytes] = []
        done = 0
        while True:
            buf = resp.read(1 << 18)
            if not buf:
                break
            done += len(buf)
            if done > max_bytes:
                raise ValueError(f"下载流超过安全上限 ({max_bytes} B)，已中止。")
            chunks.append(buf)
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
    """Query GitHub REST API DIRECTLY (never through an untrusted mirror) to obtain release tag & trusted digests."""
    del mirror_prefix  # Security rule: release metadata & digests MUST come directly from official GitHub.
    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        raw = _http_get_bytes(api_url, timeout=timeout, accept="application/vnd.github+json", max_bytes=2 * 1024 * 1024)
        data = json.loads(raw.decode("utf-8"))
        tag = str(data.get("tag_name") or "").strip()
        if not _TAG_RE.match(tag):
            raise ValueError(f"Unexpected release tag from GitHub API: {tag!r}")
        expected_prefix = f"https://github.com/{repo}/releases/download/{tag}/"
        assets: dict[str, dict[str, Any]] = {}
        for item in data.get("assets") or []:
            name = str(item.get("name") or "")
            dl_url = str(item.get("browser_download_url") or "")
            if not name or not dl_url.startswith(expected_prefix):
                continue
            raw_digest = str(item.get("digest") or "").strip()
            dm = _DIGEST_RE.match(raw_digest)
            assets[name] = {
                "name": name,
                "size": int(item.get("size") or 0),
                "url": dl_url,
                "sha256": dm.group(1).lower() if dm else "",
            }
        return {
            "source": "github_api_direct",
            "repo": repo,
            "tag": tag,
            "name": str(data.get("name") or tag),
            "published_at": str(data.get("published_at") or ""),
            "html_url": f"https://github.com/{repo}/releases/tag/{tag}",
            "assets": assets,
        }
    except Exception as exc:
        raise RuntimeError(
            "无法直连官方 GitHub API 获取可信版本与摘要（出于安全红线，禁止从第三方镜像信任代码摘要；"
            f"将自动使用内置已校验脚本）：{exc}"
        ) from exc


def _validate_tar_member_path(name: str) -> tuple[str, ...]:
    if not name or "\x00" in name:
        raise ValueError(f"Refusing empty or NUL tar path: {name!r}")
    if any(ord(c) < 32 for c in name):
        raise ValueError(f"Refusing control character in tar path: {name!r}")
    norm = name.replace("\\", "/")
    if norm.startswith("/") or re.match(r"^[A-Za-z]:", norm):
        raise ValueError(f"Refusing absolute or drive-prefixed tar path: {name!r}")
    parts = [p for p in norm.split("/") if p not in ("", ".")]
    if not parts:
        raise ValueError(f"Refusing root-only tar entry: {name!r}")
    for part in parts:
        if part == "..":
            raise ValueError(f"Refusing path traversal in tar entry: {name!r}")
        if part.startswith(" ") or part.endswith(" ") or part.endswith("."):
            raise ValueError(f"Refusing Windows leading/trailing space or trailing dot component: {name!r}")
        if any(c in _WIN_INVALID_CHARS for c in part):
            raise ValueError(f"Refusing Windows forbidden filename character in tar entry: {name!r}")
        stem = part.split(".", 1)[0].strip().upper()
        if stem in _WIN_RESERVED_NAMES:
            raise ValueError(f"Refusing Windows reserved device name in tar entry: {name!r}")
    return tuple(parts)


def _safe_extract_tar_gz(archive: Path, dst_dir: Path) -> Path:
    """Safely stream-extract release source tarball: regular files & dirs ONLY, data filter required, bounded limits."""
    if dst_dir.exists():
        shutil.rmtree(dst_dir)
    dst_dir.mkdir(parents=True, exist_ok=True)
    root = dst_dir.resolve()
    top_dirs: set[str] = set()
    seen_entries: dict[str, str] = {}  # lower rel path -> 'file' | 'dir'
    total_entries = 0
    total_files = 0
    total_bytes = 0

    with tarfile.open(archive, "r:gz") as tf:
        while (member := tf.next()) is not None:
            total_entries += 1
            if total_entries > MAX_EXTRACTED_ENTRIES:
                raise ValueError(f"Tarball entry count exceeds safety limit ({MAX_EXTRACTED_ENTRIES})")
            if not (member.isfile() or member.isdir()):
                raise ValueError(f"Refusing non-regular tar entry (symlinks/hardlinks/devices forbidden): {member.name}")
            parts = _validate_tar_member_path(member.name)
            rel_key = "/".join(parts).lower()
            kind = "file" if member.isfile() else "dir"
            if rel_key in seen_entries:
                raise ValueError(f"Refusing duplicate or conflicting tar entry ({seen_entries[rel_key]} vs {kind}): {member.name}")
            # Reject file colliding with an already-created parent directory or vice versa
            for depth in range(1, len(parts)):
                ancestor_key = "/".join(parts[:depth]).lower()
                if seen_entries.get(ancestor_key) == "file":
                    raise ValueError(f"Refusing tar entry colliding with file ancestor: {member.name}")
            seen_entries[rel_key] = kind

            if member.isfile():
                total_files += 1
                total_bytes += max(0, int(member.size))
                if total_files > MAX_EXTRACTED_FILES:
                    raise ValueError(f"Tarball file count exceeds safety limit ({MAX_EXTRACTED_FILES})")
                if total_bytes > MAX_EXTRACTED_BYTES:
                    raise ValueError(f"Tarball extracted size exceeds safety limit ({MAX_EXTRACTED_BYTES} B)")

            dest = (root / Path(*parts)).resolve()
            dest.relative_to(root)
            top_dirs.add(parts[0])
            # Extract using the exact validated normalized path so tarfile never diverges from validation.
            member.name = "/".join(parts)
            member.mode &= 0o777
            # Strictly require Python 3.11.4+ / 3.12+ `filter="data"` with zero unfiltered fallback.
            tf.extract(member, root, filter="data")

    if len(top_dirs) == 1:
        nested = root / next(iter(top_dirs))
        if nested.is_dir() and (nested / "scripts" / "kit.py").is_file():
            return nested
    if (root / "scripts" / "kit.py").is_file():
        return root
    raise RuntimeError(f"解压后的源码包缺少 scripts/kit.py：{root}")


def verify_kit_compatibility(
    kit_root: Path,
    *,
    min_protocol_version: int = KIT_MIN_PROTOCOL_VERSION,
    max_protocol_version: int = KIT_MAX_PROTOCOL_VERSION,
    expected_openwrt_base_sha256: str = PINNED_PUBLIC_OPENWRT_BASE_SHA256,
) -> dict[str, Any]:
    """Ensure a kit tree implements exact supported GUI worker protocol (AST-checked) AND pins public OpenWrt 25.12.5 pack."""
    import ast

    kit_py = kit_root / "scripts" / "kit.py"
    manifest_p = kit_root / "assets" / "release-manifest.json"
    build_py = kit_root / "scripts" / "build_images.py"
    if not kit_py.is_file() or not manifest_p.is_file() or not build_py.is_file():
        raise ValueError(f"Kit tree incomplete (missing kit.py, build_images.py, or release-manifest.json): {kit_root}")

    kit_txt = kit_py.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(kit_txt, filename=str(kit_py))
    proto_ver: int | None = None
    str_literals: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "KIT_PROTOCOL_VERSION" and isinstance(node.value, ast.Constant) and isinstance(node.value.value, int):
                    proto_ver = node.value.value
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            str_literals.add(node.value)

    if proto_ver is None or not (min_protocol_version <= proto_ver <= max_protocol_version):
        raise ValueError(
            f"Incompatible worker kit protocol version {proto_ver!r} outside supported [{min_protocol_version}, {max_protocol_version}]"
        )
    for req_flag in ("--secrets-stdin", "--expected-plan-sha256", "rollback-a"):
        if req_flag not in str_literals:
            raise ValueError(f"Incompatible worker kit missing required CLI capability literal {req_flag!r}")

    build_txt = build_py.read_text(encoding="utf-8", errors="replace")
    if EXPECTED_OPENWRT_ROOTFS not in build_txt:
        raise ValueError(f"Kit build_images.py does not pin public {EXPECTED_OPENWRT_ROOTFS}")

    manifest_raw = manifest_p.read_text(encoding="utf-8", errors="replace")
    manifest = json.loads(manifest_raw)
    ow_pack = (manifest.get("packs") or {}).get("openwrt_base") or {}
    got_ow_sha = str(ow_pack.get("sha256") or "").lower()
    if got_ow_sha != expected_openwrt_base_sha256.lower():
        raise ValueError(
            f"Kit release-manifest.json openwrt_base SHA-256 mismatch ({got_ow_sha[:16]} != {expected_openwrt_base_sha256[:16]}); "
            "refusing non-pinned OpenWrt firmware catalog."
        )

    combined_low = (kit_txt + "\n" + build_txt + "\n" + manifest_raw).lower()
    for bad in FORBIDDEN_PERSONAL_MARKERS:
        if bad in combined_low:
            raise ValueError(f"Kit violates pure public 25.12.5 policy (matched {bad!r})")

    return {"protocol_version": proto_ver, "openwrt_rootfs": EXPECTED_OPENWRT_ROOTFS, "openwrt_base_sha256": got_ow_sha}


def _build_kit_file_manifest(kit_root: Path) -> dict[str, dict[str, Any]]:
    files: dict[str, dict[str, Any]] = {}
    for p in sorted(kit_root.rglob("*")):
        if _is_link_or_reparse(p):
            raise ValueError(f"Unexpected symlink/reparse point inside extracted kit: {p}")
        if not p.is_file():
            continue
        rel = p.relative_to(kit_root).as_posix()
        files[rel] = {"size": p.stat().st_size, "sha256": sha256_file(p)}
    return files


def verify_cached_kit_tree(
    tag_dir: Path,
    *,
    expected_src_sha256: str | None = None,
    min_tag: str = "",
) -> dict[str, Any] | None:
    """Verify `.kit_verified.json`, archive digest binding, every file SHA-256, zero links/extras, and worker protocol."""
    marker = tag_dir / ".kit_verified.json"
    try:
        if _is_link_or_reparse(tag_dir) or not tag_dir.is_dir():
            return None
        if _is_link_or_reparse(marker) or not marker.is_file():
            return None
        rec = json.loads(marker.read_text(encoding="utf-8"))
        if not isinstance(rec, dict):
            return None
        tag = str(rec.get("tag") or "")
        if not _TAG_RE.match(tag) or tag != tag_dir.name:
            return None
        if min_tag:
            min_sv = parse_semver(min_tag)
            cur_sv = parse_semver(tag)
            if min_sv is not None and (cur_sv is None or cur_sv < min_sv):
                return None
        if rec.get("trust_source") not in ("github_api_digest", "github_direct_sha256sums"):
            return None
        rec_src_sha = str(rec.get("src_sha256") or "").lower()
        if len(rec_src_sha) != 64:
            return None
        if expected_src_sha256 is not None and rec_src_sha != expected_src_sha256.lower():
            return None
        # Bind against stored source tarball if present next to tag_dir
        arc_path = tag_dir.parent / f"f50pro-dualboot-kit-{tag}-src.tar.gz"
        if expected_src_sha256 is not None:
            if not arc_path.is_file() or _is_link_or_reparse(arc_path) or sha256_file(arc_path) != expected_src_sha256.lower():
                return None

        rel_root = str(rec.get("kit_root_rel") or "")
        kit_root = (tag_dir / rel_root).resolve() if rel_root else tag_dir.resolve()
        kit_root.relative_to(tag_dir.resolve())
        if _is_link_or_reparse(kit_root) or not kit_root.is_dir():
            return None
        files_map = rec.get("files")
        if not isinstance(files_map, dict) or not files_map:
            return None
        if "scripts/kit.py" not in files_map or "assets/release-manifest.json" not in files_map:
            return None

        expected_rels: set[str] = set()
        for rel, spec in files_map.items():
            if not isinstance(rel, str) or not isinstance(spec, dict):
                return None
            parts = _validate_tar_member_path(rel)
            cur = kit_root
            for part in parts:
                cur = cur / part
                if _is_link_or_reparse(cur):
                    return None
            cand = cur.resolve()
            cand.relative_to(kit_root)
            if not cand.is_file():
                return None
            exp_sha = spec.get("sha256")
            if not isinstance(exp_sha, str) or len(exp_sha) != 64:
                return None
            if cand.stat().st_size != int(spec["size"]) or sha256_file(cand) != exp_sha:
                return None
            expected_rels.add(cur.relative_to(kit_root).as_posix())

        actual_rels: set[str] = set()
        for p in kit_root.rglob("*"):
            if _is_link_or_reparse(p):
                return None
            if p == marker:
                continue
            if p.is_file():
                actual_rels.add(p.relative_to(kit_root).as_posix())
        if actual_rels != expected_rels:
            return None

        compat = verify_kit_compatibility(kit_root)
        return {
            "tag": tag,
            "kit_root": kit_root,
            "src_sha256": rec_src_sha,
            "trust_source": rec["trust_source"],
            "protocol_version": compat["protocol_version"],
        }
    except Exception:
        return None


def _resolve_trusted_source_digest(
    release_info: dict[str, Any],
    src_name: str,
    *,
    log_cb: Callable[[str], None] | None = None,
) -> tuple[str, str, str]:
    """Resolve (src_url, expected_sha256, trust_source) DIRECTLY from official GitHub (never via mirror)."""
    tag = str(release_info.get("tag") or "")
    assets = release_info.get("assets") or {}
    if src_name not in assets:
        raise RuntimeError(f"Release {tag} 缺少 {src_name}。")
    src_meta = assets[src_name]
    src_url = str(src_meta.get("url") or "")
    if not src_url.startswith(f"https://github.com/{GITHUB_REPO}/releases/download/{tag}/"):
        raise RuntimeError(f"源码包 URL 不在官方仓库发布路径下：{src_url}")

    expected_sha = str(src_meta.get("sha256") or "").lower()
    if len(expected_sha) == 64:
        return src_url, expected_sha, "github_api_digest"

    if "SHA256SUMS.txt" not in assets:
        raise RuntimeError(f"Release {tag} 既无 GitHub API 原生摘要也无 SHA256SUMS.txt，拒绝拉取。")
    sums_url = str(assets["SHA256SUMS.txt"].get("url") or "")
    if not sums_url.startswith(f"https://github.com/{GITHUB_REPO}/releases/download/{tag}/"):
        raise RuntimeError(f"SHA256SUMS.txt URL 不在官方仓库发布路径下：{sums_url}")
    if log_cb:
        log_cb(f"直连官方 GitHub 获取可信校验清单（禁止走镜像）：{sums_url}")
    sums_bytes = _http_get_bytes(sums_url, timeout=30.0, max_bytes=512 * 1024)
    sums = parse_sha256sums(sums_bytes.decode("utf-8", errors="replace"))
    expected_sha = sums.get(src_name, "")
    if len(expected_sha) != 64:
        raise RuntimeError(f"官方 SHA256SUMS.txt 中未包含 {src_name} 的有效 SHA-256 校验值。")
    return src_url, expected_sha, "github_direct_sha256sums"


def download_and_verify_kit_release(
    release_info: dict[str, Any],
    *,
    kit_store_dir: Path,
    mirror_prefix: str = "",
    min_tag: str = "",
    log_cb: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Download latest compatible source tarball via mirror/direct, strictly anchored to direct official GitHub SHA-256."""
    tag = str(release_info.get("tag") or "")
    if not _TAG_RE.match(tag):
        raise ValueError(f"Invalid release tag: {tag!r}")
    if release_info.get("source") != "github_api_direct":
        raise RuntimeError("拒绝从未通过官方 GitHub API 直连验证的发布元数据拉取代码。")

    if min_tag:
        min_sv = parse_semver(min_tag)
        cur_sv = parse_semver(tag)
        if min_sv is not None and (cur_sv is None or cur_sv < min_sv):
            raise RuntimeError(
                f"远端 Release {tag} 低于当前内置安全基线版本 {min_tag}，拒绝降级（将继续使用内置脚本）。"
            )

    src_name = f"f50pro-dualboot-kit-{tag}-src.tar.gz"
    # ALWAYS anchor expected_sha directly from GitHub BEFORE inspecting any local cache!
    src_url, expected_sha, trust_source = _resolve_trusted_source_digest(release_info, src_name, log_cb=log_cb)

    with _cross_process_tag_lock(kit_store_dir, tag):
        target_wrap = kit_store_dir / tag
        cached = verify_cached_kit_tree(target_wrap, expected_src_sha256=expected_sha, min_tag=min_tag)
        if cached is not None:
            if log_cb:
                log_cb(f"[OK] 本地可信缓存的 {tag} 脚本与官方摘要及协议完全一致，直接使用。")
            return {"status": "cached", **cached}

        kit_store_dir.mkdir(parents=True, exist_ok=True)
        stage_id = f"{os.getpid()}-{uuid.uuid4().hex[:8]}"
        archive_part = kit_store_dir / f".{src_name}.{stage_id}.part"
        stage_dir = kit_store_dir / f".stage-{tag}-{stage_id}"

        verified = False
        last_err: Exception | None = None
        try:
            for cand in build_candidate_urls(src_url, mirror_prefix):
                if log_cb:
                    log_cb(f"下载 {tag} 刷机脚本包正文：{cand}")
                try:
                    data = _http_get_bytes(cand, timeout=90.0, max_bytes=MAX_ARCHIVE_BYTES)
                    archive_part.write_bytes(data)
                    actual_sha = sha256_file(archive_part)
                    if actual_sha != expected_sha:
                        archive_part.unlink(missing_ok=True)
                        raise ValueError(
                            f"SHA-256 校验不匹配（镜像文件可能已被篡改或损坏）：{actual_sha[:16]} != {expected_sha[:16]}"
                        )
                    verified = True
                    break
                except Exception as exc:
                    last_err = exc
                    archive_part.unlink(missing_ok=True)
                    if log_cb:
                        log_cb(f"[WARN] 下载/校验失败（自动回退备用地址）：{exc}")
            if not verified:
                raise RuntimeError(f"无法获取通过官方 SHA-256 校验的 {src_name}：{last_err}")

            if log_cb:
                log_cb(f"[OK] {src_name} 官方摘要校验通过（{trust_source}: {expected_sha[:12]}...），安全解压与协议核验中...")
            staged_kit_root = _safe_extract_tar_gz(archive_part, stage_dir)
            compat = verify_kit_compatibility(staged_kit_root)

            files_manifest = _build_kit_file_manifest(staged_kit_root)
            rel_root = staged_kit_root.relative_to(stage_dir.resolve()).as_posix()
            (stage_dir / ".kit_verified.json").write_text(
                json.dumps(
                    {
                        "tag": tag,
                        "kit_root_rel": "" if rel_root == "." else rel_root,
                        "src_sha256": expected_sha,
                        "trust_source": trust_source,
                        "protocol_version": compat["protocol_version"],
                        "files": files_manifest,
                    },
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )

            final_archive = kit_store_dir / src_name
            os.replace(archive_part, final_archive)

            # Atomically swap staged directory into target_wrap
            if target_wrap.exists():
                old_tmp = kit_store_dir / f".old-{tag}-{stage_id}"
                os.replace(target_wrap, old_tmp)
                try:
                    os.replace(stage_dir, target_wrap)
                except Exception:
                    os.replace(old_tmp, target_wrap)
                    raise
                shutil.rmtree(old_tmp, ignore_errors=True)
            else:
                os.replace(stage_dir, target_wrap)

            final_check = verify_cached_kit_tree(target_wrap, expected_src_sha256=expected_sha, min_tag=min_tag)
            if final_check is None:
                raise RuntimeError(f"落盘后复核 {tag} 缓存完整性或协议兼容性失败。")
            return {"status": "downloaded", **final_check}
        finally:
            archive_part.unlink(missing_ok=True)
            if stage_dir.exists():
                shutil.rmtree(stage_dir, ignore_errors=True)


def resolve_kit_version(kit_root: Path) -> str:
    """Read human-friendly version label from a local or cached kit directory."""
    for candidate_dir in (kit_root, kit_root.parent):
        marker = candidate_dir / ".kit_verified.json"
        if marker.is_file():
            try:
                return str(json.loads(marker.read_text(encoding="utf-8")).get("tag") or "local")
            except Exception:
                pass
    guide = kit_root / "docs" / "beginner-guide.md"
    if guide.is_file():
        m = re.search(
            r"f50pro-dualboot-kit\s+(v[0-9]+\.[0-9]+\.[0-9]+)",
            guide.read_text(encoding="utf-8", errors="ignore"),
        )
        if m:
            return m.group(1)
    return "bundled"
