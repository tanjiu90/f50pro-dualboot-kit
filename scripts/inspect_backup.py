"""Inspect a verified F50 Pro BROM backup without storing raw PII/secrets."""
from __future__ import annotations

import argparse
import json
import re
import struct
from pathlib import Path
from typing import Any

from common import (
    REPO_ROOT,
    TRUSTOS_AVB_SIG_OFFSET,
    TRUSTOS_AVB_SIG_ORIG,
    align_up,
    decompress_lz4_legacy,
    parse_avb_footer,
    parse_boot_control,
    parse_dhtb_header,
    parse_newc_cpio,
    parse_simghdr,
    sha256_bytes,
    write_json,
)


def _extract_ramdisk_bytes(image: bytes) -> bytes:
    page = 4096
    k_sz = struct.unpack_from("<I", image, 8)[0]
    r_sz = struct.unpack_from("<I", image, 12)[0]
    r_off = page + align_up(k_sz, page)
    return image[r_off : r_off + r_sz]


def _is_arm64_prologue(insn: int) -> bool:
    return (insn & 0xFFC07FFF) == 0xA9807BFD or (insn & 0xFFC003FF) == 0xD10003FF


def _locate_arm64_dis_avb(trustos_bytes: bytes, payload_sz: int) -> int | None:
    """Port of upstream ARM64 dis_avb xref + epilogue scanner for Unisoc trustos."""
    dhtb = 0x200
    end = min(len(trustos_bytes), dhtb + payload_sz)
    mem = trustos_bytes[:end]
    marker = mem.find(b"### enter avb_slot_verify. ###")
    if marker < 0:
        marker = mem.find(b"enter avb_slot_verify")
    if marker < dhtb:
        return None
    target = marker - dhtb
    page = [0] * 32
    valid = [False] * 32
    ref = -1
    for i in range(dhtb, len(mem) - 4, 4):
        insn = struct.unpack_from("<I", mem, i)[0]
        if (insn & 0x9F000000) == 0x90000000:
            rd = insn & 31
            imm = (((insn >> 5) & 0x7FFFF) << 2) | ((insn >> 29) & 3)
            if imm & (1 << 20):
                imm -= 1 << 21
            page[rd] = (((i - dhtb) & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFFFFFF
            valid[rd] = True
        elif (insn & 0xFF800000) == 0x91000000:
            rn = (insn >> 5) & 31
            imm12 = (insn >> 10) & 0xFFF
            if insn & (1 << 22):
                imm12 <<= 12
            if valid[rn] and page[rn] + imm12 == target:
                ref = i
                break
    if ref < 0:
        return None

    lo = dhtb
    for i in range(ref, dhtb, -4):
        if struct.unpack_from("<I", mem, i - 4)[0] == 0xD65F03C0:
            lo = i
            break
    scan_lo = lo
    for i in range(lo, ref, 4):
        if _is_arm64_prologue(struct.unpack_from("<I", mem, i)[0]):
            scan_lo = i
            break
    scan_hi = len(mem)
    seen_ret = False
    for i in range(scan_lo + 4, len(mem) - 4, 4):
        insn = struct.unpack_from("<I", mem, i)[0]
        if insn == 0xD65F03C0:
            seen_ret = True
        elif seen_ret and _is_arm64_prologue(insn):
            scan_hi = i
            break

    start_pos = 0
    hits: list[int] = []
    for i in range(scan_lo, scan_hi - 32 + 1, 4):
        cur = struct.unpack_from("<I", mem, i)[0]
        if cur == 0xD65F03C0 or (cur & 0xFF00FFFF) == 0xA8007BFD:
            start_pos = 0
        elif (cur & 0xFF00FFFF) == 0xA9007BFD:
            start_pos = i
        elif start_pos:
            ldp = 0
            for m in range(0, 20, 4):
                if mem[i + m + 3] == 0xA9:
                    ldp += 1
                else:
                    break
            if ldp == 5 and any(struct.unpack_from("<I", mem, i + m)[0] == 0xD65F03C0 for m in range(24, 32, 4)):
                if i >= dhtb + 8 and struct.unpack_from("<H", mem, i - 4)[0] == 0x03E0 and mem[i - 7] == 0x03:
                    c1 = sum(1 for m in range(start_pos, i, 4) if (struct.unpack_from("<I", mem, m)[0] >> 16) == 0x9400)
                    c2 = sum(1 for m in range(start_pos, i, 4) if (struct.unpack_from("<I", mem, m)[0] >> 16) == 0xB400)
                    if c1 and c2 and (c1 + c2 > 2):
                        hits.append((i - 4) - dhtb)
    return hits[-1] if hits else None


def locate_trustos_patch_offset(trustos_bytes: bytes) -> dict[str, Any]:
    """Locate the unique AVB check instruction offset inside this device's trustos payload."""
    dhtb = parse_dhtb_header(trustos_bytes)
    simg = parse_simghdr(trustos_bytes, trailer_offset=dhtb["trailer_offset"])
    payload = trustos_bytes[0x200 : 0x200 + simg["data_sz"]]
    arm_off = _locate_arm64_dis_avb(trustos_bytes, simg["data_sz"])
    if arm_off is not None:
        return {
            "patch_code_offset": arm_off,
            "patch_code_hex": hex(arm_off),
            "payload_size": simg["data_sz"],
            "method": "arm64_dis_avb",
        }
    hits = []
    start = 0
    while True:
        idx = payload.find(TRUSTOS_AVB_SIG_ORIG, start)
        if idx < 0:
            break
        hits.append(idx + TRUSTOS_AVB_SIG_OFFSET)
        start = idx + 1
    if len(hits) != 1:
        raise ValueError(f"Expected exactly 1 trustos AVB signature match, found {len(hits)}: {hits}")
    return {
        "patch_code_offset": hits[0],
        "patch_code_hex": hex(hits[0]),
        "payload_size": simg["data_sz"],
        "method": "context_signature",
    }


def inspect_vendor_boot(vb_bytes: bytes) -> dict[str, Any]:
    """Extract DTB digest, dtbo_idx, and hardware string from stock vendor_boot_a."""
    if not vb_bytes.startswith(b"VNDRBOOT"):
        raise ValueError("Missing VNDRBOOT header")
    hdr_ver, page, _ka, _ra, v_ram_sz = struct.unpack_from("<5I", vb_bytes, 8)
    hdr_sz, dtb_sz, _dtb_addr = struct.unpack_from("<IIQ", vb_bytes, 2096)
    tbl_sz, _n, _es, bc_sz = struct.unpack_from("<4I", vb_bytes, 2112)
    off_ram = align_up(hdr_sz, page)
    off_dtb = off_ram + align_up(v_ram_sz, page)
    off_bc = off_dtb + align_up(dtb_sz, page) + align_up(tbl_sz, page)
    dtb = vb_bytes[off_dtb : off_dtb + dtb_sz]
    bc = vb_bytes[off_bc : off_bc + bc_sz].rstrip(b"\x00\n").decode("utf-8", "replace")
    return {
        "header_version": hdr_ver,
        "dtb_size": dtb_sz,
        "dtb_sha256": sha256_bytes(dtb),
        "bootconfig": [ln for ln in bc.splitlines() if ln.strip()],
    }


def inspect_init_boot(ib_bytes: bytes) -> dict[str, Any]:
    """Read Android build properties and AVB metadata from init_boot_a."""
    cpio_raw = decompress_lz4_legacy(_extract_ramdisk_bytes(ib_bytes))
    entries = parse_newc_cpio(cpio_raw)
    props: dict[str, str] = {}
    for entry in entries:
        if entry["name"] == "system/etc/ramdisk/build.prop":
            for line in entry["data"].decode("utf-8", "replace").splitlines():
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    props[k.strip()] = v.strip()
    footer = parse_avb_footer(ib_bytes)
    return {
        "entry_count": len(entries),
        "avb_offset": footer["vbmeta_offset"],
        "avb_size": footer["vbmeta_size"],
        "model": props.get("ro.product.bootimage.model"),
        "sdk": props.get("ro.bootimage.build.version.sdk"),
        "fingerprint": props.get("ro.bootimage.build.fingerprint"),
        "incremental": props.get("ro.bootimage.build.version.incremental"),
    }


def inspect_boot_banner(boot_bytes: bytes) -> dict[str, Any]:
    """Identify stock Android GKI kernel banner from boot_a."""
    k_sz = struct.unpack_from("<I", boot_bytes, 8)[0]
    m = re.search(rb"Linux version [^\x00\n]{10,160}", boot_bytes[4096 : 4096 + k_sz])
    return {
        "kernel_size": k_sz,
        "kernel_banner": m.group(0).decode("ascii", "replace") if m else None,
        "avb": parse_avb_footer(boot_bytes),
    }


def inspect_backup_dir(backup_dir: Path, out_path: Path | None = None) -> dict[str, Any]:
    """Audit a BROM backup directory and confirm MU3356 F50 Pro compatibility."""
    boot_info = inspect_boot_banner((backup_dir / "boot_a").read_bytes())
    vb_info = inspect_vendor_boot((backup_dir / "vendor_boot_a").read_bytes())
    ib_info = inspect_init_boot((backup_dir / "init_boot_a").read_bytes())
    misc_info = parse_boot_control((backup_dir / "misc").read_bytes())
    tos_info = locate_trustos_patch_offset((backup_dir / "trustos_a").read_bytes())

    hw_ok = any("ums9632" in item for item in vb_info["bootconfig"]) and ib_info["model"] == "MU3356"
    if not hw_ok:
        raise ValueError(f"Unsupported device: model={ib_info['model']}, bootconfig={vb_info['bootconfig']}")

    fulldump_sz = (backup_dir / "fulldumpdb").stat().st_size
    empty_b = {
        p: not any((backup_dir / p).read_bytes()[:65536])
        for p in ("boot_b", "vendor_boot_b", "init_boot_b")
    }

    report = {
        "device_family": "ZTE F50 Pro (MU3356 / UMS9632)",
        "supported": True,
        "boot_a": boot_info,
        "vendor_boot_a": vb_info,
        "init_boot_a": ib_info,
        "misc": misc_info,
        "trustos_a": tos_info,
        "fulldumpdb_bytes": fulldump_sz,
        "slot_b_initially_empty": empty_b,
        "variant_notes": {
            "board_id=6 (插卡版, e.g. B28)": "Supports physical Nano-SIM + eSIM mux; OpenWrt patches f50pro-card.sh cleanly.",
            "board_id=1 (内置双 eSIM 版, e.g. B15)": "No physical SIM slot (is_support_psim=0); CM/CT dual eSIM onboard; unactivated cards show stat=8 red net LED.",
        },
    }
    if out_path is not None:
        write_json(out_path, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    bdir = args.backup_dir if args.backup_dir.is_absolute() else (REPO_ROOT / args.backup_dir)
    out = (args.out if args.out.is_absolute() else (REPO_ROOT / args.out)) if args.out else None
    print(json.dumps(inspect_backup_dir(bdir, out), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
