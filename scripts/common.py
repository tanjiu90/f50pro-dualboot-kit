"""Shared binary parsers, constants, profiles, and safety guardrails."""
from __future__ import annotations

import hashlib
import json
import lzma
import shutil
import stat
import struct
import subprocess
import zlib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
ASSETS_DIR = REPO_ROOT / "assets"
MANIFEST_PATH = ASSETS_DIR / "release-manifest.json"
DEFAULT_TOOLS_DIR = REPO_ROOT / "build" / "runtime-tools"
DEFAULT_CACHE_DIR = REPO_ROOT / "bundle-cache"

# Partitions that MUST NEVER be modified by automated flashing workflows.
FORBIDDEN_PARTITIONS = frozenset({
    "splloader",
    "prodnv",
    "calinv",
    "ztecfg",
    "ztepersist",
    "persist",
    "miscdata",
    "super",
    "userdata",
    "nr_fixnv1",
    "nr_fixnv2",
    "nr_runtimenv1",
    "nr_runtimenv2",
    "l_fixnv1",
    "l_fixnv2",
    "l_runtimenv1",
    "l_runtimenv2",
    "nr_cali",
    "l_cali",
})

BSP_SLOT_SYNC_PAIRS: tuple[tuple[str, str], ...] = (
    ("uboot_a", "uboot_b"),
    ("sml_a", "sml_b"),
    ("teecfg_a", "teecfg_b"),
    ("dtbo_a", "dtbo_b"),
    ("vbmeta_a", "vbmeta_b"),
    ("vbmeta_system_a", "vbmeta_system_b"),
    ("vbmeta_vendor_a", "vbmeta_vendor_b"),
    ("vbmeta_system_ext_a", "vbmeta_system_b_ext_placeholder"),
)
# Exact 12 A->B stock BSP pairs mirrored to slot _b for F50 Pro MU3356:
BSP_SYNC_PAIRS_F50PRO: tuple[tuple[str, str], ...] = (
    ("uboot_a", "uboot_b"),
    ("sml_a", "sml_b"),
    ("teecfg_a", "teecfg_b"),
    ("dtbo_a", "dtbo_b"),
    ("vbmeta_a", "vbmeta_b"),
    ("vbmeta_system_a", "vbmeta_system_b"),
    ("vbmeta_vendor_a", "vbmeta_vendor_b"),
    ("vbmeta_system_ext_a", "vbmeta_system_ext_b"),
    ("vbmeta_product_a", "vbmeta_product_b"),
    ("vbmeta_odm_a", "vbmeta_odm_b"),
    ("logo_a", "logo_b"),
    ("fbootlogo_a", "fbootlogo_b"),
)

# Unique 64-byte context around the 4-byte TEE AVB verdict instruction (e0031a2a -> 00008052).
# Verified identical across MU3356 B15 (0x981ec) and MU3356 B28 (0x9856c).
TRUSTOS_AVB_SIG_ORIG = bytes.fromhex(
    "04020054760a00b0f6420791880240f9082140b91f0d00718b010054e10300aa"
    "e0031a2a04000094a8000037000100f060623f91a0f8ff97fb0300aaf7030014"
)
TRUSTOS_AVB_SIG_OFFSET = 32
TRUSTOS_ORIG_OPCODE = bytes.fromhex("e0031a2a")
TRUSTOS_PATCH_OPCODE = bytes.fromhex("00008052")

F50PRO_VENDOR_BOOT_EXTRA_ARGS = (
    "u30pro_sim_mux.layout=mu3356 "
    "u30pro_ump965x_fgu.battery_present=0 "
    "u30pro_sgm41513.battery_present=0 "
    "f50pro_external_power_only=1"
)

PROFILES: dict[str, dict[str, Any]] = {
    "1-android-ufi": {
        "name": "Android Root + UFI-TOOLS (Single Slot _a)",
        "touches_slot_a": True,
        "touches_slot_b": False,
        "android_root": True,
        "openwrt": False,
        "default_usb_mode": "rndis,serial_smd,diag,adb",
    },
    "2-dual-stock-openwrt": {
        "name": "Stock Android (_a untouched) + OpenWrt 25.12.5 (_b)",
        "touches_slot_a": False,
        "touches_slot_b": True,
        "android_root": False,
        "openwrt": True,
        "default_usb_mode": None,
    },
    "3-dual-full": {
        "name": "Full Dual-Boot: Android Root + UFI-TOOLS (_a) + OpenWrt 25.12.5 (_b) + 5s Switch",
        "touches_slot_a": True,
        "touches_slot_b": True,
        "android_root": True,
        "openwrt": True,
        "default_usb_mode": "charging,adb",
    },
}

LZ4_LEGACY_MAGIC = b"\x02\x21\x4c\x18"
BOOT_MAGIC = b"ANDROID!"
VENDOR_BOOT_MAGIC = b"VNDRBOOT"
AVB_FOOTER_MAGIC = b"AVBf"
AVB0_MAGIC = b"AVB0"
MISC_BC_OFFSET = 2048
SUPPORTED_BOARD_VARIANTS = {
    "1": "F50 Pro 内置双 eSIM 版 (board_id=1, CM+CT eSIM, is_support_psim=0)",
    "6": "F50 Pro 插卡版 (board_id=6, 外置 Nano-SIM + 内置 eSIM 切换)",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def align_up(value: int, page_size: int) -> int:
    return ((value + page_size - 1) // page_size) * page_size


def xz_compress_crc32(data: bytes) -> bytes:
    """Compress payload into XZ stream using CRC32 check (compatible with Magisk/Linux xz)."""
    return lzma.compress(data, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32, preset=9)


def parse_dhtb_header(data: bytes) -> dict[str, int]:
    """Parse Unisoc DHTB signed container header."""
    if len(data) < 0x200 or data[:4] != b"DHTB":
        raise ValueError("Missing DHTB magic")
    payload_sz = struct.unpack_from("<I", data, 0x30)[0]
    trailer_offset = 0x200 + payload_sz
    if trailer_offset > len(data):
        raise ValueError(f"DHTB payload size exceeds file length: {trailer_offset} > {len(data)}")
    return {"payload_sz": payload_sz, "trailer_offset": trailer_offset}


def parse_simghdr(data: bytes, trailer_offset: int) -> dict[str, int]:
    """Parse Unisoc SIMGHDR footer located right after the DHTB payload."""
    chunk = data[trailer_offset:]
    if len(chunk) < 0x30 or chunk[:8] != b"SIMGHDR\x00":
        raise ValueError("Missing SIMGHDR trailer")
    return {
        "data_sz": struct.unpack_from("<I", chunk, 0x10)[0],
        "pay_off": struct.unpack_from("<I", chunk, 0x18)[0],
        "cert_off": struct.unpack_from("<I", chunk, 0x28)[0],
    }


def dhtb_data_size(data: bytes) -> int:
    """Compute exact Unisoc DHTB+SIMGHDR+certificate footprint, stripping partition zero tail."""
    dhtb = parse_dhtb_header(data)
    raw_end = dhtb["trailer_offset"]
    if raw_end + 0x60 > len(data):
        return raw_end
    max_end = raw_end + 0x60
    for sz_off, off_off in ((0x20, 0x28), (0x30, 0x38), (0x50, 0x58)):
        seg_sz = struct.unpack_from("<Q", data, raw_end + sz_off)[0]
        seg_off = struct.unpack_from("<Q", data, raw_end + off_off)[0]
        if seg_sz and seg_off and seg_off + seg_sz > max_end and seg_off + seg_sz <= len(data):
            max_end = seg_off + seg_sz
    return max_end


def parse_boot_control(misc_bytes: bytes) -> dict[str, Any]:
    """Decode Android bootloader_control structure at misc+2048."""
    if len(misc_bytes) < MISC_BC_OFFSET + 32:
        raise ValueError("misc image smaller than 2080 bytes")
    blk = misc_bytes[MISC_BC_OFFSET : MISC_BC_OFFSET + 32]
    if blk[4:8] != b"BCAB":
        raise ValueError(f"Invalid BCAB magic at misc+2048: {blk[4:8]!r}")
    crc_stored = struct.unpack_from("<I", blk, 28)[0]
    crc_calc = zlib.crc32(blk[:28]) & 0xFFFFFFFF
    if crc_stored != crc_calc:
        raise ValueError(f"BCAB CRC32 mismatch: stored=0x{crc_stored:08x} calc=0x{crc_calc:08x}")
    suffix = blk[:4].split(b"\x00", 1)[0].decode("ascii", "replace")
    slots = {}
    for idx, name in ((12, "a"), (14, "b")):
        info = blk[idx]
        slots[name] = {
            "priority": info & 0x0F,
            "tries_remaining": (info >> 4) & 0x07,
            "successful": bool((info >> 7) & 0x01),
            "raw_byte": info,
        }
    return {
        "suffix": suffix,
        "version": blk[8],
        "nb_slot": blk[9],
        "slots": slots,
        "crc32": f"0x{crc_stored:08x}",
        "raw_hex": blk.hex(),
    }


def build_trial_bcab(current_blk: bytes, target_slot: str, tries: int = 3) -> bytes:
    """Build 32-byte BCAB trial block targeting 'a' or 'b' with fallback to opposite slot."""
    if len(current_blk) != 32 or current_blk[4:8] != b"BCAB":
        raise ValueError("Invalid current BCAB block")
    if target_slot not in ("a", "b") or not (1 <= tries <= 7):
        raise ValueError("Invalid target slot or tries count")
    blk = bytearray(current_blk)
    blk[:4] = f"_{target_slot}".encode("ascii") + b"\x00\x00"
    active_off, fallback_off = (12, 14) if target_slot == "a" else (14, 12)
    blk[active_off] = 15 | (tries << 4)
    blk[active_off + 1] &= ~1
    blk[fallback_off] = (blk[fallback_off] & 0xF0) | 14
    struct.pack_into("<I", blk, 28, zlib.crc32(blk[:28]) & 0xFFFFFFFF)
    return bytes(blk)


def parse_avb_footer(image: bytes) -> dict[str, int]:
    """Read 64-byte AVB0 footer at end of an Android partition image."""
    if len(image) < 64:
        raise ValueError("Image smaller than 64 bytes")
    footer = image[-64:]
    if footer[:4] != AVB_FOOTER_MAGIC:
        raise ValueError("Missing AVBf footer at image tail")
    major, minor, orig_size, vbmeta_offset, vbmeta_size = struct.unpack_from(">IIQQQ", footer, 4)
    if image[vbmeta_offset : vbmeta_offset + 4] != AVB0_MAGIC:
        raise ValueError(f"Missing AVB0 header at 0x{vbmeta_offset:x}")
    return {
        "major": major,
        "minor": minor,
        "original_image_size": orig_size,
        "vbmeta_offset": vbmeta_offset,
        "vbmeta_size": vbmeta_size,
    }


def decompress_lz4_legacy(blob: bytes) -> bytes:
    """Decompress Linux/Android LZ4-legacy stream using pure Python."""
    if not blob.startswith(LZ4_LEGACY_MAGIC):
        raise ValueError("Not an LZ4-legacy stream")
    pos = 4
    out = bytearray()
    total = len(blob)
    while pos + 4 <= total:
        blk_sz = struct.unpack_from("<I", blob, pos)[0]
        pos += 4
        if blk_sz == 0 or pos + blk_sz > total:
            break
        block = blob[pos : pos + blk_sz]
        pos += blk_sz
        bpos = 0
        while bpos < len(block):
            token = block[bpos]
            bpos += 1
            lit_len = token >> 4
            if lit_len == 15:
                while bpos < len(block):
                    add = block[bpos]
                    bpos += 1
                    lit_len += add
                    if add != 255:
                        break
            out.extend(block[bpos : bpos + lit_len])
            bpos += lit_len
            if bpos >= len(block):
                break
            match_off = struct.unpack_from("<H", block, bpos)[0]
            bpos += 2
            match_len = (token & 0x0F) + 4
            if (token & 0x0F) == 15:
                while bpos < len(block):
                    add = block[bpos]
                    bpos += 1
                    match_len += add
                    if add != 255:
                        break
            if match_off == 0 or match_off > len(out):
                raise ValueError(f"Invalid LZ4 backreference offset {match_off}")
            for _ in range(match_len):
                out.append(out[-match_off])
    return bytes(out)


def encode_lz4_legacy_stored(payload: bytes) -> bytes:
    """Encode payload as uncompressed LZ4-legacy blocks (pure Python, zero dependencies)."""
    out = bytearray(LZ4_LEGACY_MAGIC)
    max_lit = 4 << 20
    for start in range(0, max(1, len(payload)), max_lit):
        chunk = payload[start : start + max_lit]
        lit_len = len(chunk)
        blk = bytearray()
        if lit_len < 15:
            blk.append(lit_len << 4)
        else:
            blk.append(0xF0)
            rem = lit_len - 15
            while rem >= 255:
                blk.append(255)
                rem -= 255
            blk.append(rem)
        blk.extend(chunk)
        out.extend(struct.pack("<I", len(blk)))
        out.extend(blk)
    return bytes(out)


def parse_newc_cpio(blob: bytes) -> list[dict[str, Any]]:
    """Parse SVR4 newc (070701) CPIO archive until TRAILER!!!."""
    entries: list[dict[str, Any]] = []
    pos = 0
    while pos + 110 <= len(blob):
        magic = blob[pos : pos + 6]
        if magic != b"070701":
            raise ValueError(f"Unexpected CPIO magic at 0x{pos:x}: {magic!r}")
        hdr = blob[pos : pos + 110].decode("ascii")
        fields = [int(hdr[6 + i * 8 : 14 + i * 8], 16) for i in range(13)]
        mode, filesize, namesize = fields[1], fields[6], fields[11]
        name_start = pos + 110
        name = blob[name_start : name_start + namesize - 1].decode("utf-8", "replace")
        data_start = align_up(name_start + namesize, 4)
        data = blob[data_start : data_start + filesize]
        pos = align_up(data_start + filesize, 4)
        if name == "TRAILER!!!":
            break
        entries.append({"name": name, "mode": mode, "data": data})
    return entries


def encode_newc_cpio(entries: list[dict[str, Any]]) -> bytes:
    """Encode list of {name, mode, data} dicts into SVR4 newc (070701) CPIO bytes."""
    out = bytearray()
    for ino, item in enumerate(entries, 1):
        name_b = item["name"].encode("utf-8") + b"\x00"
        data = item["data"]
        mode = item["mode"]
        nlink = 2 if stat.S_ISDIR(mode) else 1
        fields = [ino, mode, 0, 0, nlink, 0, len(data), 0, 0, 0, 0, len(name_b), 0]
        hdr = b"070701" + "".join(f"{x:08x}" for x in fields).encode("ascii") + name_b
        out.extend(hdr)
        out.extend(b"\x00" * ((-len(hdr)) % 4))
        out.extend(data)
        out.extend(b"\x00" * ((-len(data)) % 4))
    tname = b"TRAILER!!!\x00"
    tfields = [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(tname), 0]
    thdr = b"070701" + "".join(f"{x:08x}" for x in tfields).encode("ascii") + tname
    out.extend(thdr)
    out.extend(b"\x00" * ((-len(thdr)) % 4))
    return bytes(out)


def repack_boot_v4_with_avb(
    template: bytes,
    *,
    kernel: bytes | None = None,
    ramdisk: bytes | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Repack Android boot/init_boot v4 image preserving template AVB0/AVBf framing."""
    if not template.startswith(BOOT_MAGIC):
        raise ValueError("Missing ANDROID! magic")
    header_ver = struct.unpack_from("<I", template, 40)[0]
    if header_ver != 4:
        raise ValueError(f"Expected boot header v4, got {header_ver}")
    footer = parse_avb_footer(template)
    vbmeta = template[footer["vbmeta_offset"] : footer["vbmeta_offset"] + footer["vbmeta_size"]]
    old_k_sz = struct.unpack_from("<I", template, 8)[0]
    old_r_sz = struct.unpack_from("<I", template, 12)[0]
    page = 4096
    old_k_start = page
    old_r_start = old_k_start + align_up(old_k_sz, page)
    new_k = template[old_k_start : old_k_start + old_k_sz] if kernel is None else kernel
    new_r = template[old_r_start : old_r_start + old_r_sz] if ramdisk is None else ramdisk

    payload = bytearray(template[:page])
    struct.pack_into("<II", payload, 8, len(new_k), len(new_r))
    if new_k:
        payload.extend(new_k.ljust(align_up(len(new_k), page), b"\x00"))
    if new_r:
        payload.extend(new_r.ljust(align_up(len(new_r), page), b"\x00"))

    new_vbmeta_off = len(payload)
    if new_vbmeta_off + len(vbmeta) + 64 > len(template):
        raise ValueError(
            f"Repacked payload ({new_vbmeta_off} B) + AVB exceeds partition ({len(template)} B)"
        )
    out = bytearray(len(template))
    out[:new_vbmeta_off] = payload
    out[new_vbmeta_off : new_vbmeta_off + len(vbmeta)] = vbmeta
    new_footer = bytearray(template[-64:])
    struct.pack_into(">QQ", new_footer, 12, new_vbmeta_off, new_vbmeta_off)
    out[-64:] = new_footer
    result = bytes(out)
    return result, {
        "partition_size": len(result),
        "kernel_size": len(new_k),
        "ramdisk_size": len(new_r),
        "avb_offset": new_vbmeta_off,
        "avb_size": len(vbmeta),
        "sha256": sha256_bytes(result),
    }


def repack_vendor_boot_v4(
    template: bytes,
    extra_bootconfig: str,
    *,
    expected_dtb_sha256: str,
    ramdisk: bytes,
) -> tuple[bytes, dict[str, Any]]:
    """Repack vendor_boot v4 keeping device-native DTB and updating vendor_ramdisk + bootconfig."""
    if not template.startswith(VENDOR_BOOT_MAGIC):
        raise ValueError("Missing VNDRBOOT magic")
    header_ver, page, _k_addr, _r_addr, v_ram_sz = struct.unpack_from("<5I", template, 8)
    if header_ver != 4:
        raise ValueError(f"Expected vendor_boot v4, got {hdr_ver}")
    hdr_sz, dtb_sz, _dtb_addr = struct.unpack_from("<IIQ", template, 2096)
    tbl_sz, tbl_num, tbl_ent_sz, bc_sz = struct.unpack_from("<4I", template, 2112)
    footer = parse_avb_footer(template)
    vbmeta = template[footer["vbmeta_offset"] : footer["vbmeta_offset"] + footer["vbmeta_size"]]

    off_ram = align_up(hdr_sz, page)
    off_dtb = off_ram + align_up(v_ram_sz, page)
    off_tbl = off_dtb + align_up(dtb_sz, page)
    off_bc = off_tbl + align_up(tbl_sz, page)

    dtb_bytes = template[off_dtb : off_dtb + dtb_sz]
    if sha256_bytes(dtb_bytes) != expected_dtb_sha256:
        raise ValueError("vendor_boot_a DTB digest mismatch")
    old_tbl = bytearray(template[off_tbl : off_tbl + tbl_sz])
    if len(old_tbl) < 4:
        old_tbl = bytearray(tbl_ent_sz)
    struct.pack_into("<I", old_tbl, 0, len(ramdisk))
    old_bc_raw = template[off_bc : off_bc + bc_sz]

    cur_cmd = template[28:2076].split(b"\x00", 1)[0].decode("ascii", errors="strict")
    cmd_tokens = cur_cmd.split()
    for tok in extra_bootconfig.split():
        if tok not in cmd_tokens:
            cmd_tokens.append(tok)
    new_cmd = " ".join(cmd_tokens)
    cmd_bytes = new_cmd.encode("ascii") + b"\x00"
    if len(cmd_bytes) > 2048:
        raise ValueError("Combined vendor_boot cmdline exceeds 2048 bytes")

    hdr = bytearray(template[:off_ram])
    hdr[28:2076] = cmd_bytes.ljust(2048, b"\x00")
    struct.pack_into("<I", hdr, 24, len(ramdisk))
    struct.pack_into("<4I", hdr, 2112, len(old_tbl), 1, tbl_ent_sz, len(old_bc_raw))

    payload = bytearray(hdr)
    payload.extend(ramdisk.ljust(align_up(len(ramdisk), page), b"\x00"))
    payload.extend(dtb_bytes.ljust(align_up(len(dtb_bytes), page), b"\x00"))
    payload.extend(bytes(old_tbl).ljust(align_up(len(old_tbl), page), b"\x00"))
    payload.extend(old_bc_raw.ljust(align_up(len(old_bc_raw), page), b"\x00"))

    new_vbmeta_off = len(payload)
    if new_vbmeta_off + len(vbmeta) + 64 > len(template):
        raise ValueError("Repacked vendor_boot_b exceeds partition size")
    out = bytearray(len(template))
    out[:new_vbmeta_off] = payload
    out[new_vbmeta_off : new_vbmeta_off + len(vbmeta)] = vbmeta
    new_footer = bytearray(template[-64:])
    struct.pack_into(">QQQ", new_footer, 12, new_vbmeta_off, new_vbmeta_off, len(vbmeta))
    out[-64:] = new_footer
    result = bytes(out)
    return result, {
        "partition_size": len(result),
        "ramdisk_size": len(ramdisk),
        "dtb_sha256": expected_dtb_sha256,
        "cmdline": new_cmd,
        "avb_offset": new_vbmeta_off,
        "sha256": sha256_bytes(result),
    }


def resolve_tool(name: str, tools_dir: Path = DEFAULT_TOOLS_DIR) -> Path:
    """Resolve bundled or system PATH executable (spd_dump, adb, etc.)."""
    candidates = {
        "spd_dump": [
            tools_dir / "host-tools-win64/spd_dump_251/spd_dump.exe",
            tools_dir / "spd_dump_251/spd_dump.exe",
        ],
        "adb": [
            tools_dir / "host-tools-win64/platform-tools/adb.exe",
            tools_dir / "platform-tools/adb.exe",
        ],
    }
    for cand in candidates.get(name, []):
        if cand.is_file():
            return cand
    found = shutil.which(name)
    if found:
        return Path(found)
    raise FileNotFoundError(f"Tool '{name}' not found in {tools_dir} or PATH. Run bootstrap/fetch-assets first.")
