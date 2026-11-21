"""Download, SHA-256 verify, and extract selectable multi-platform Release packs."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from common import (
    DEFAULT_CACHE_DIR,
    DEFAULT_TOOLS_DIR,
    HOST_PLATFORMS,
    MANIFEST_PATH,
    REPO_ROOT,
    detect_host_platform,
    ensure_executable,
    is_link_or_reparse,
    read_json,
    sha256_file,
)

PLATFORM_PACK_MAP: dict[str, str] = {
    "win64": "host_tools_win64",
    "linux-x64": "host_tools_linux_x64",
    "linux-arm64": "host_tools_linux_arm64",
    "macos": "host_tools_macos",
    "android-arm64": "host_tools_android_arm64",
}

PROFILE_PACK_MAP: dict[str, tuple[str, ...]] = {
    "all": ("openwrt_base", "android_pkgs"),
    "1-android-ufi": ("android_pkgs",),
    "2-dual-stock-openwrt": ("openwrt_base",),
    "3-dual-full": ("openwrt_base", "android_pkgs"),
    "none": (),
}


def select_pack_keys(
    manifest: dict[str, Any],
    *,
    host_platform: str = "auto",
    profile: str = "all",
    include_openclash: bool = True,
    explicit_packs: list[str] | None = None,
) -> list[str]:
    """Resolve the ordered list of manifest pack keys to fetch based on OS and profile filters."""
    packs = manifest["packs"]
    if explicit_packs:
        out: list[str] = []
        for raw in explicit_packs:
            for item in raw.split(","):
                key = item.strip()
                if not key:
                    continue
                if key not in packs:
                    raise ValueError(f"Unknown release pack '{key}'; available: {sorted(packs)}")
                if key not in out:
                    out.append(key)
        return out

    if profile not in PROFILE_PACK_MAP:
        raise ValueError(f"Unknown profile filter '{profile}'; choices: {sorted(PROFILE_PACK_MAP)}")

    selected: list[str] = list(PROFILE_PACK_MAP[profile])
    if include_openclash and profile in ("all", "2-dual-stock-openwrt", "3-dual-full"):
        if "openclash_offline" in packs:
            selected.append("openclash_offline")

    if host_platform == "none":
        pass
    elif host_platform == "all":
        for pkey in PLATFORM_PACK_MAP.values():
            if pkey in packs and pkey not in selected:
                selected.append(pkey)
    elif host_platform == "auto":
        detected = detect_host_platform()
        pkey = PLATFORM_PACK_MAP.get(detected)
        if pkey and pkey in packs and pkey not in selected:
            selected.append(pkey)
    else:
        for raw in host_platform.split(","):
            plat = raw.strip()
            if not plat:
                continue
            if plat not in PLATFORM_PACK_MAP:
                raise ValueError(
                    f"Unsupported host platform '{plat}'; choices: auto, all, none, {', '.join(HOST_PLATFORMS)}"
                )
            pkey = PLATFORM_PACK_MAP[plat]
            if pkey not in packs:
                raise ValueError(f"Manifest missing host-tools pack '{pkey}' for platform '{plat}'")
            if pkey not in selected:
                selected.append(pkey)

    # Filter non-optional firmware packs only when absent in stripped synthetic test manifests.
    return [k for k in selected if k in packs]


def list_available_packs(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Return human- and agent-readable catalog of downloadable Release assets."""
    base_url = manifest["base_url"].rstrip("/")
    rows: list[dict[str, Any]] = []
    for key, meta in manifest["packs"].items():
        rows.append(
            {
                "pack": key,
                "filename": meta["filename"],
                "bytes": meta.get("bytes"),
                "mib": round(meta["bytes"] / (1024 * 1024), 2) if meta.get("bytes") else None,
                "sha256": meta["sha256"],
                "platforms": meta.get("platforms", ["all"]),
                "profiles": meta.get("profiles", ["all"]),
                "optional": bool(meta.get("optional", False)),
                "description": meta.get("description", ""),
                "url": f"{base_url}/{meta['filename']}",
            }
        )
    return rows


def interactive_select(manifest: dict[str, Any]) -> tuple[str, str, bool]:
    """Prompt terminal user to choose host platform pack(s), profile filter, and OpenClash."""
    detected = detect_host_platform()
    print(f"Detected host platform: {detected}", file=sys.stderr)
    print("\nSelect host tool bundle to download:", file=sys.stderr)
    plat_opts = [
        ("1", detected, f"Current host ({detected}) [default]"),
        ("2", "win64", "Windows x64"),
        ("3", "linux-x64", "Linux x86_64"),
        ("4", "linux-arm64", "Linux ARM64 / aarch64"),
        ("5", "macos", "macOS Universal (Apple Silicon + Intel)"),
        ("6", "android-arm64", "Android ARM64 Termux (Root su + --usb-fd)"),
        ("7", "all", "Download ALL host tool packs (mirror / multi-machine USB stick)"),
        ("8", "none", "Skip host tools (firmware packs only)"),
    ]
    for idx, _, label in plat_opts:
        print(f"  [{idx}] {label}", file=sys.stderr)
    p_ans = input("Host tool choice [1]: ").strip() or "1"
    host_platform = next((val for idx, val, _ in plat_opts if idx == p_ans), p_ans)

    print("\nSelect deployment profile assets to download:", file=sys.stderr)
    prof_opts = [
        ("1", "3-dual-full", "Dual-boot full assets (OpenWrt + Android Root + APKs) [default]"),
        ("2", "1-android-ufi", "Profile 1 only (Android Root + UFI-TOOLS APKs; skips OpenWrt)"),
        ("3", "2-dual-stock-openwrt", "Profile 2 only (Stock Android untouched + OpenWrt; skips APKs)"),
        ("4", "none", "Host tools only (skip firmware & APK packs)"),
    ]
    for idx, _, label in prof_opts:
        print(f"  [{idx}] {label}", file=sys.stderr)
    f_ans = input("Profile asset choice [1]: ").strip() or "1"
    profile = next((val for idx, val, _ in prof_opts if idx == f_ans), f_ans)

    include_openclash = False
    if profile in ("all", "2-dual-stock-openwrt", "3-dual-full"):
        oc_ans = input("Include optional offline OpenClash pack (~36 MiB)? [Y/n]: ").strip().lower()
        include_openclash = oc_ans not in ("n", "no", "0", "false")
    return host_platform, profile, include_openclash


def _download_file(url: str, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(dst.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "f50pro-dualboot-kit/1.1"})
    print(f"Downloading {url} ...", file=sys.stderr)
    with urllib.request.urlopen(req, timeout=180) as resp, tmp.open("wb") as out:
        while chunk := resp.read(1 << 20):
            out.write(chunk)
    tmp.replace(dst)


def _locate_or_fetch_archive(
    meta: dict[str, Any],
    base_url: str,
    cache_dir: Path,
    local_release_dir: Path | None,
    *,
    offline_only: bool = False,
) -> tuple[Path, str | None]:
    fname = meta["filename"]
    expected = meta["sha256"]
    candidates = [cache_dir / fname]
    if local_release_dir is not None:
        candidates.insert(0, local_release_dir / fname)
    for cand in candidates:
        if cand.is_file():
            if sha256_file(cand) != expected:
                raise ValueError(f"SHA-256 mismatch on local archive {cand}")
            return cand, None

    if offline_only:
        raise FileNotFoundError(
            f"Offline mode forbids network download and archive {fname} is missing from cache/local dir"
        )

    dst = cache_dir / fname
    url = f"{base_url.rstrip('/')}/{fname}"
    _download_file(url, dst)
    actual = sha256_file(dst)
    if actual != expected:
        dst.unlink(missing_ok=True)
        raise ValueError(f"Downloaded archive {fname} SHA-256 mismatch: {actual} != {expected}")
    return dst, url


def _safe_extract_zip(archive: Path, target_dir: Path) -> list[str]:
    target_dir.mkdir(parents=True, exist_ok=True)
    root = target_dir.resolve()
    names = []
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            dest = (root / info.filename).resolve()
            dest.relative_to(root)
            zf.extract(info, root)
            if os.name != "nt" and not info.is_dir():
                unix_mode = (info.external_attr >> 16) & 0o777
                if unix_mode & stat.S_IXUSR:
                    ensure_executable(dest)
            names.append(info.filename)
    return names


def _safe_extract_tar(archive: Path, target_dir: Path) -> list[str]:
    target_dir.mkdir(parents=True, exist_ok=True)
    root = target_dir.resolve()
    names = []
    with tarfile.open(archive, "r:*") as tf:
        for member in tf.getmembers():
            if member.isdev() or member.isfifo() or not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise ValueError(f"Refusing to extract special device/FIFO/unsupported tar entry: {member.name}")
            if Path(member.name).is_absolute():
                raise ValueError(f"Refusing to extract absolute tar path: {member.name}")
            dest = (root / member.name).resolve()
            dest.relative_to(root)
            if member.issym():
                link_target = (dest.parent / member.linkname).resolve()
                link_target.relative_to(root)
            elif member.islnk():
                link_target = (root / member.linkname).resolve()
                link_target.relative_to(root)
            member.mode &= 0o777
            try:
                tf.extract(member, root, filter="data")
            except TypeError:
                tf.extract(member, root)
            if os.name != "nt" and member.isfile() and (member.mode & 0o111):
                ensure_executable(dest)
            names.append(member.name)
    return names


def _build_extracted_manifest(sub_out: Path, archive_sha256: str) -> dict[str, Any]:
    """Record size and SHA-256 of every extracted file under sub_out to detect deleted/corrupt/extra cache trees."""
    files_meta: dict[str, dict[str, Any]] = {}
    for p in sorted(sub_out.rglob("*")):
        if not p.is_file():
            continue
        if p.name in (".verified.sha256", ".verified.manifest.json"):
            continue
        rel = p.relative_to(sub_out).as_posix()
        files_meta[rel] = {"size": p.stat().st_size, "sha256": sha256_file(p)}
    return {"archive_sha256": archive_sha256, "files": files_meta}


def _is_extracted_cache_valid(sub_out: Path, expected_archive_sha: str) -> bool:
    """Return True only if marker AND exact set of extracted files exist with intact size & SHA-256 (zero extras/links/junctions)."""
    marker = sub_out / ".verified.sha256"
    manifest_f = sub_out / ".verified.manifest.json"
    try:
        if is_link_or_reparse(sub_out) or not sub_out.is_dir():
            return False
        if is_link_or_reparse(marker) or is_link_or_reparse(manifest_f):
            return False
        if not marker.is_file() or marker.read_text(encoding="utf-8").strip() != expected_archive_sha:
            return False
        if not manifest_f.is_file():
            return False
        rec = read_json(manifest_f)
        if not isinstance(rec, dict) or rec.get("archive_sha256") != expected_archive_sha:
            return False
        files_map = rec.get("files")
        if not isinstance(files_map, dict) or not files_map:
            return False
        root = sub_out.resolve()
        expected_rels: set[str] = set()
        for rel, spec in files_map.items():
            if not isinstance(rel, str) or not isinstance(spec, dict):
                return False
            rel_parts = Path(rel).parts
            if not rel_parts or Path(rel).is_absolute():
                return False
            cur = sub_out
            for part in rel_parts:
                if part in ("", ".", ".."):
                    return False
                cur = cur / part
                if is_link_or_reparse(cur):
                    return False
            raw_cand = cur
            cand = raw_cand.resolve()
            cand.relative_to(root)
            if not cand.is_file():
                return False
            exp_sz = int(spec["size"])
            exp_sha = spec.get("sha256")
            if not isinstance(exp_sha, str) or len(exp_sha) != 64:
                return False
            if cand.stat().st_size != exp_sz or sha256_file(cand) != exp_sha:
                return False
            expected_rels.add(raw_cand.relative_to(sub_out).as_posix())
        # Reject ANY unexpected/unverified extra file, symlink, or NTFS junction dropped into the extracted directory.
        actual_rels: set[str] = set()
        for p in sub_out.rglob("*"):
            if is_link_or_reparse(p):
                return False
            if p.name in (".verified.sha256", ".verified.manifest.json") and p.parent == sub_out:
                continue
            if p.is_file():
                actual_rels.add(p.relative_to(sub_out).as_posix())
        return actual_rels == expected_rels
    except Exception:
        return False


def _clean_dir_contents(target_dir: Path) -> None:
    if is_link_or_reparse(target_dir):
        try:
            target_dir.unlink()
        except OSError:
            os.rmdir(target_dir)
    elif target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)


def fetch_and_extract(
    *,
    include_openclash: bool = True,
    host_platform: str = "auto",
    profile: str = "all",
    explicit_packs: list[str] | None = None,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    tools_dir: Path = DEFAULT_TOOLS_DIR,
    local_release_dir: Path | None = None,
    offline_only: bool = False,
) -> dict[str, Any]:
    """Download/locate, SHA-256 verify, and extract selected Release packs."""
    manifest = read_json(MANIFEST_PATH)
    base_url = manifest["base_url"]
    packs = manifest["packs"]
    if local_release_dir is None:
        local_release_dir = REPO_ROOT / "dist" / f"release-{manifest['release_tag']}"

    selected = select_pack_keys(
        manifest,
        host_platform=host_platform,
        profile=profile,
        include_openclash=include_openclash,
        explicit_packs=explicit_packs,
    )

    extracted: dict[str, Any] = {}
    network_downloads: list[str] = []
    for key in selected:
        meta = packs[key]
        arc, downloaded_url = _locate_or_fetch_archive(
            meta,
            base_url,
            cache_dir,
            local_release_dir,
            offline_only=offline_only,
        )
        if downloaded_url:
            network_downloads.append(downloaded_url)
        sub_out = tools_dir / key.replace("_", "-")
        marker = sub_out / ".verified.sha256"
        manifest_f = sub_out / ".verified.manifest.json"
        if _is_extracted_cache_valid(sub_out, meta["sha256"]):
            extracted[key] = {"archive": str(arc), "dir": str(sub_out), "status": "cached"}
            continue
        _clean_dir_contents(sub_out)
        files = (
            _safe_extract_zip(arc, sub_out)
            if arc.suffix == ".zip"
            else _safe_extract_tar(arc, sub_out)
        )
        # Verify nested Magisk / UFI APK digests if present
        if key == "android_pkgs":
            for apk_name, apk_sha in meta.get("contains", {}).items():
                if apk_sha:
                    got = sha256_file(sub_out / apk_name)
                    if got != apk_sha:
                        raise ValueError(f"{apk_name} SHA-256 mismatch: {got} != {apk_sha}")
        ext_manifest = _build_extracted_manifest(sub_out, meta["sha256"])
        manifest_f.write_text(json.dumps(ext_manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        marker.write_text(meta["sha256"] + "\n", encoding="utf-8")
        extracted[key] = {
            "archive": str(arc),
            "dir": str(sub_out),
            "files": len(files),
            "status": "extracted",
        }
    return {
        "manifest_tag": manifest["release_tag"],
        "detected_platform": detect_host_platform(),
        "requested_platform": host_platform,
        "profile_filter": profile,
        "selected_packs": selected,
        "offline_only": offline_only,
        "network_downloads": network_downloads,
        "tools_dir": str(tools_dir),
        "packs": extracted,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-openclash", action="store_true", help="Skip optional OpenClash offline bundle")
    parser.add_argument(
        "--host-platform",
        default="auto",
        help="Host tool pack selector: auto, win64, linux-x64, linux-arm64, macos, android-arm64, all, none, or comma-separated list",
    )
    parser.add_argument(
        "--profile",
        default="all",
        choices=sorted(PROFILE_PACK_MAP),
        help="Filter firmware/APK bundles needed by a specific flash profile",
    )
    parser.add_argument(
        "--packs",
        nargs="+",
        help="Explicitly specify manifest pack keys (e.g. --packs host_tools_macos openwrt_base)",
    )
    parser.add_argument("--list-packs", action="store_true", help="List downloadable packs with sizes, SHA-256s, and URLs")
    parser.add_argument("--interactive", action="store_true", help="Prompt interactively for platform, profile, and OpenClash")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    parser.add_argument("--local-release-dir", type=Path)
    parser.add_argument("--offline-only", action="store_true", help="Fail instead of downloading missing packs")
    args = parser.parse_args()

    manifest = read_json(MANIFEST_PATH)
    if args.list_packs:
        print(
            json.dumps(
                {
                    "release_tag": manifest["release_tag"],
                    "detected_platform": detect_host_platform(),
                    "packs": list_available_packs(manifest),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    host_plat = args.host_platform
    prof = args.profile
    inc_oc = not args.no_openclash
    if args.interactive:
        host_plat, prof, inc_oc = interactive_select(manifest)

    res = fetch_and_extract(
        include_openclash=inc_oc,
        host_platform=host_plat,
        profile=prof,
        explicit_packs=args.packs,
        cache_dir=args.cache_dir,
        tools_dir=args.tools_dir,
        local_release_dir=args.local_release_dir,
        offline_only=args.offline_only,
    )
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
