"""Sanitization, raw-backup filename gate, and release-manifest integrity audits."""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

from common import MANIFEST_PATH, REPO_ROOT, sha256_file

FORBIDDEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key_header", re.compile(r"BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|PRIVATE) KEY")),
    (
        "github_or_cloud_token",
        re.compile(
            r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{10,}\b"
            r"|\b(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{20,})\b"
        ),
    ),
    (
        "ssh_public_key_material",
        re.compile(r"\b(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256)\s+[A-Za-z0-9+/=]{32,}"),
    ),
    ("raw_imei_15_digits", re.compile(r"(?<![0-9a-fA-F])86\d{13}(?![0-9a-fA-F])")),
    (
        "raw_iccid_or_imsi",
        re.compile(r"(?<![0-9a-fA-F])(?:8986\d{14,16}|460\d{12})(?![0-9a-fA-F])"),
    ),
    (
        "proxy_subscription_uri",
        re.compile(r"\b(?:vmess|vless|trojan|ssr|hysteria2?|tuic)://[^\s\"'<>`]+", re.I),
    ),
    (
        "local_windows_user_path",
        re.compile(
            r"[A-Za-z]:[/\\]+Users[/\\]+(?!(?:Public|Default|runneradmin)\b|<)[A-Za-z0-9._-]+",
            re.I,
        ),
    ),
    (
        "local_unix_user_path",
        re.compile(r"(?:/Users|/home)/(?!(?:runner|ubuntu|user|admin)\b|<)[a-z_][a-z0-9._-]*(?=/|$)"),
    ),
)

FORBIDDEN_TRACKED_FILENAMES: frozenset[str] = frozenset(
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


def _load_extra_local_patterns() -> list[tuple[str, re.Pattern[str]]]:
    """Load optional untracked local regex rules (never committed to Git)."""
    env_p = os.environ.get("F50PRO_SANITIZE_PATTERNS_FILE")
    cand = Path(env_p) if env_p else (REPO_ROOT / "tmp" / "sanitize-local.patterns")
    if not cand.is_file():
        return []
    out: list[tuple[str, re.Pattern[str]]] = []
    for idx, raw in enumerate(cand.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "::" in line:
            label, expr = line.split("::", 1)
        else:
            label, expr = f"local_rule_{idx}", line
        out.append((label.strip(), re.compile(expr)))
    return out


def _iter_repo_tracked_files() -> list[tuple[str, bytes]]:
    """Enumerate Git-tracked paths via NUL-delimited `git ls-files -z` and scan BOTH staged index blobs and worktree bytes."""
    res = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "-z"],
        capture_output=True,
        check=True,
    )
    items: list[tuple[str, bytes]] = []
    for raw_rel in res.stdout.split(b"\x00"):
        if not raw_rel:
            continue
        rel = raw_rel.decode("utf-8")
        idx_res = subprocess.run(["git", "-C", str(REPO_ROOT), "show", f":{rel}"], capture_output=True)
        idx_bytes = idx_res.stdout if idx_res.returncode == 0 else None
        p = REPO_ROOT / rel
        wt_bytes = p.read_bytes() if p.is_file() else None
        if idx_bytes is not None:
            items.append((f"index:{rel}", idx_bytes))
        if wt_bytes is not None and wt_bytes != idx_bytes:
            items.append((rel, wt_bytes))
    return items


def test_no_secrets_or_device_pii_in_repo_files() -> None:
    """Ensure every tracked/staged repo file (UTF-8 and non-UTF-8) is strictly free of PII, secrets, or raw backups."""
    patterns = [*FORBIDDEN_PATTERNS, *_load_extra_local_patterns()]
    violations: list[str] = []
    for rel, raw in _iter_repo_tracked_files():
        fname = Path(rel).name.lower()
        if fname in FORBIDDEN_TRACKED_FILENAMES or fname.endswith((".pem", ".key")):
            violations.append(f"{rel}: forbidden tracked raw-backup or secret filename")
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1", errors="ignore")
        for label, pat in patterns:
            if pat.search(text):
                violations.append(f"{rel}: matched {label}")
    assert not violations, f"Sanitization violations detected: {violations}"


def test_openclash_template_is_clean() -> None:
    """Ensure bundled template.yaml contains zero personal proxy providers or nodes."""
    tpl = (REPO_ROOT / "assets/openwrt-patch/openclash-clean/template.yaml").read_text(encoding="utf-8")
    assert "proxies: []" in tpl
    assert "proxy-providers" not in tpl.lower()
    assert not re.search(r"(?<![a-z-])(?:server|password|uuid|private-key|sni):", tpl, re.I)


def test_release_manifest_matches_local_dist_when_present() -> None:
    """Verify release-manifest.json sizes and SHA-256 digests match dist/release-v1.1.0 if built locally."""
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    dist_dir = REPO_ROOT / "dist" / f"release-{manifest['release_tag']}"
    if not dist_dir.is_dir():
        return
    for key, meta in manifest["packs"].items():
        arc = dist_dir / meta["filename"]
        assert arc.is_file(), f"Missing release pack {arc}"
        assert arc.stat().st_size == meta["bytes"], f"{key} byte count mismatch"
        assert sha256_file(arc) == meta["sha256"], f"{key} SHA-256 mismatch"
