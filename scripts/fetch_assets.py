"""Download, SHA-256 verify, and extract Release v1.0.0 offline tool/package packs."""
from __future__ import annotations

import argparse
import json
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from common import (
    DEFAULT_CACHE_DIR,
    DEFAULT_TOOLS_DIR,
    MANIFEST_PATH,
    REPO_ROOT,
    read_json,
    sha256_file,
)


def _download_file(url: str, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(dst.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "f50pro-dualboot-kit/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp, tmp.open("wb") as out:
        while chunk := resp.read(1 << 20):
            out.write(chunk)
    tmp.replace(dst)


def _locate_or_fetch_archive(
    meta: dict[str, Any],
    base_url: str,
    cache_dir: Path,
    local_release_dir: Path | None,
) -> Path:
    fname = meta["filename"]
    expected = meta["sha256"]
    candidates = [cache_dir / fname]
    if local_release_dir is not None:
        candidates.insert(0, local_release_dir / fname)
    for cand in candidates:
        if cand.is_file():
            if sha256_file(cand) != expected:
                raise ValueError(f"SHA-256 mismatch on local archive {cand}")
            return cand

    dst = cache_dir / fname
    url = f"{base_url.rstrip('/')}/{fname}"
    _download_file(url, dst)
    actual = sha256_file(dst)
    if actual != expected:
        dst.unlink(missing_ok=True)
        raise ValueError(f"Downloaded archive {fname} SHA-256 mismatch: {actual} != {expected}")
    return dst


def _safe_extract_zip(archive: Path, target_dir: Path) -> list[str]:
    target_dir.mkdir(parents=True, exist_ok=True)
    root = target_dir.resolve()
    names = []
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            dest = (root / info.filename).resolve()
            dest.relative_to(root)
            zf.extract(info, root)
            names.append(info.filename)
    return names


def _safe_extract_tar(archive: Path, target_dir: Path) -> list[str]:
    target_dir.mkdir(parents=True, exist_ok=True)
    root = target_dir.resolve()
    names = []
    with tarfile.open(archive, "r:*") as tf:
        for member in tf.getmembers():
            dest = (root / member.name).resolve()
            dest.relative_to(root)
            tf.extract(member, root)
            names.append(member.name)
    return names


def fetch_and_extract(
    *,
    include_openclash: bool = True,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    tools_dir: Path = DEFAULT_TOOLS_DIR,
    local_release_dir: Path | None = REPO_ROOT / "dist" / "release-v1.0.0",
) -> dict[str, Any]:
    """Ensure required Release v1.0.0 tool/package packs are present, verified, and extracted."""
    manifest = read_json(MANIFEST_PATH)
    base_url = manifest["base_url"]
    packs = manifest["packs"]
    selected = ["openwrt_base", "android_pkgs"]
    if sys.platform == "win32":
        selected.append("host_tools_win64")
    if include_openclash:
        selected.append("openclash_offline")

    extracted: dict[str, Any] = {}
    for key in selected:
        meta = packs[key]
        arc = _locate_or_fetch_archive(meta, base_url, cache_dir, local_release_dir)
        sub_out = tools_dir / key.replace("_", "-")
        marker = sub_out / ".verified.sha256"
        if marker.is_file() and marker.read_text(encoding="utf-8").strip() == meta["sha256"]:
            extracted[key] = {"archive": str(arc), "dir": str(sub_out), "status": "cached"}
            continue
        files = (
            _safe_extract_zip(arc, sub_out)
            if arc.suffix == ".zip"
            else _safe_extract_tar(arc, sub_out)
        )
        # Verify nested Magisk APK digest if present
        if key == "android_pkgs":
            for apk_name, apk_sha in meta.get("contains", {}).items():
                if apk_sha:
                    got = sha256_file(sub_out / apk_name)
                    if got != apk_sha:
                        raise ValueError(f"{apk_name} SHA-256 mismatch: {got} != {apk_sha}")
        marker.write_text(meta["sha256"] + "\n", encoding="utf-8")
        extracted[key] = {"archive": str(arc), "dir": str(sub_out), "files": len(files), "status": "extracted"}
    return {"manifest_tag": manifest["release_tag"], "tools_dir": str(tools_dir), "packs": extracted}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-openclash", action="store_true")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    args = parser.parse_args()
    res = fetch_and_extract(
        include_openclash=not args.no_openclash,
        cache_dir=args.cache_dir,
        tools_dir=args.tools_dir,
    )
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
