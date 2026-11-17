"""Shared synthetic A/B firmware and toolchain fixtures for zero-hardware offline tests."""
from __future__ import annotations

import base64
import hashlib
import lzma
import struct
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from common import (  # noqa: E402
    AVB0_MAGIC,
    AVB_FOOTER_MAGIC,
    BOOT_MAGIC,
    BSP_SYNC_PAIRS_F50PRO,
    TRUSTOS_AVB_SIG_ORIG,
    VENDOR_BOOT_MAGIC,
    align_up,
    encode_lz4_legacy_stored,
    encode_newc_cpio,
    zlib,
)


def make_synthetic_dhtb(payload: bytes, total_size: int = 0x20000) -> bytes:
    """Create a synthetic DHTB + SIMGHDR container matching Unisoc sml/trustos layout."""
    hdr = bytearray(0x200)
    hdr[0:4] = b"DHTB"
    struct.pack_into("<I", hdr, 0x30, len(payload))
    simg = bytearray(0x40)
    simg[0:8] = b"SIMGHDR\x00"
    struct.pack_into("<I", simg, 0x10, len(payload))
    struct.pack_into("<I", simg, 0x18, 0x200)
    struct.pack_into("<I", simg, 0x28, 0x200 + len(payload) + 0x40)
    raw = bytes(hdr) + payload + bytes(simg)
    return raw.ljust(total_size, b"\x00")


def make_synthetic_boot_v4(ramdisk: bytes, *, kernel: bytes = b"", total_size: int = 0x200000) -> bytes:
    """Build a valid Android Boot v4 image with AVB0 + AVBf 64B footer."""
    page = 4096
    hdr = bytearray(page)
    hdr[0:8] = BOOT_MAGIC
    struct.pack_into("<II", hdr, 8, len(kernel), len(ramdisk))
    struct.pack_into("<I", hdr, 20, 1584)
    struct.pack_into("<I", hdr, 40, 4)
    hdr[44:55] = b"loglevel=5\x00"
    body = bytearray(hdr)
    if kernel:
        body.extend(kernel.ljust(align_up(len(kernel), page), b"\x00"))
    body.extend(ramdisk.ljust(align_up(len(ramdisk), page), b"\x00"))
    vbmeta_off = len(body)
    vbmeta = AVB0_MAGIC + b"\x00" * 508
    out = bytearray(total_size)
    out[:vbmeta_off] = body
    out[vbmeta_off : vbmeta_off + len(vbmeta)] = vbmeta
    footer = bytearray(64)
    footer[0:4] = AVB_FOOTER_MAGIC
    struct.pack_into(">IIQQQ", footer, 4, 1, 0, vbmeta_off, vbmeta_off, len(vbmeta))
    out[-64:] = footer
    return bytes(out)


def make_synthetic_vendor_boot_v4(dtb: bytes, *, total_size: int = 0x200000) -> bytes:
    """Build a valid Android vendor_boot v4 image with DTB, bootconfig, and AVB footer."""
    page = 4096
    ram = encode_lz4_legacy_stored(encode_newc_cpio([]))
    bc = b"androidboot.hardware=ums9632_1h10_mbb\n"
    tbl = bytearray(16)
    struct.pack_into("<4I", tbl, 0, len(ram), 0, 1, 1)

    hdr = bytearray(page)
    hdr[0:8] = VENDOR_BOOT_MAGIC
    struct.pack_into("<5I", hdr, 8, 4, page, 0, 0, len(ram))
    struct.pack_into("<IIQ", hdr, 2096, 2128, len(dtb), 0)
    struct.pack_into("<4I", hdr, 2112, len(tbl), 1, 16, len(bc))

    off_ram = align_up(2128, page)
    body = bytearray(hdr[:2128].ljust(off_ram, b"\x00"))
    body.extend(ram.ljust(align_up(len(ram), page), b"\x00"))
    body.extend(dtb.ljust(align_up(len(dtb), page), b"\x00"))
    body.extend(bytes(tbl).ljust(align_up(len(tbl), page), b"\x00"))
    body.extend(bc.ljust(align_up(len(bc), page), b"\x00"))

    vbmeta_off = len(body)
    vbmeta = AVB0_MAGIC + b"\x00" * 508
    out = bytearray(total_size)
    out[:vbmeta_off] = body
    out[vbmeta_off : vbmeta_off + len(vbmeta)] = vbmeta
    footer = bytearray(64)
    footer[0:4] = AVB_FOOTER_MAGIC
    struct.pack_into(">IIQQQ", footer, 4, 1, 0, vbmeta_off, vbmeta_off, len(vbmeta))
    out[-64:] = footer
    return bytes(out)


def make_synthetic_misc(active_slot: str = "_a", total_size: int = 0x100000) -> bytes:
    """Create a 1 MiB misc image with valid CRC32 BCAB at offset 2048."""
    blk = bytearray(32)
    s_b = active_slot.encode("ascii")
    blk[: len(s_b)] = s_b
    blk[4:8] = b"BCAB"
    blk[8] = 1
    blk[12] = 0xEF if active_slot == "_a" else 0x6F
    blk[13] = 0x6F if active_slot == "_a" else 0xEF
    struct.pack_into("<I", blk, 28, zlib.crc32(blk[:28]) & 0xFFFFFFFF)
    out = bytearray(total_size)
    out[2048 : 2048 + 32] = blk
    return bytes(out)


@pytest.fixture()
def synthetic_env(tmp_path: Path) -> dict[str, Path]:
    """Create isolated backup_dir, tools_dir, adbkey.pub, and out_dir for offline profile builds."""
    backup_dir = tmp_path / "backup"
    tools_dir = tmp_path / "tools"
    out_dir = tmp_path / "build"
    backup_dir.mkdir(parents=True)
    tools_dir.mkdir(parents=True)

    # 1. Synthetic SML & TRUSTOS with unique AVB signature at custom offset 0x420
    sml_payload = b"\xaa" * 0x1800
    tos_payload = bytearray(b"\x1f\x20\x03\xd5" * (0x4000 // 4))
    sig_off = 0x420
    tos_payload[sig_off : sig_off + len(TRUSTOS_AVB_SIG_ORIG)] = TRUSTOS_AVB_SIG_ORIG
    (backup_dir / "sml_a").write_bytes(make_synthetic_dhtb(sml_payload, total_size=0x20000))
    (backup_dir / "trustos_a").write_bytes(make_synthetic_dhtb(bytes(tos_payload), total_size=0x20000))
    (backup_dir / "trustos_b").write_bytes(b"\x00" * 0x20000)

    # 2. Synthetic boot_a, vendor_boot_a, init_boot_a, misc, BSP pairs, fulldumpdb (MiB-sized XML entries >= 1 MiB)
    mib = 1 << 20
    stock_cpio = encode_newc_cpio([
        {"name": "init", "mode": 0o100755, "data": b"#!/bin/sh\necho stock init\n"},
        {
            "name": "system/etc/ramdisk/build.prop",
            "mode": 0o100644,
            "data": (
                b"ro.product.bootimage.model=MU3356\n"
                b"ro.bootimage.build.version.sdk=35\n"
                b"ro.bootimage.build.fingerprint=ZTE/MU3356/test:15\n"
                b"ro.bootimage.build.version.incremental=test1\n"
            ),
        },
    ])
    stock_ram = encode_lz4_legacy_stored(stock_cpio)
    (backup_dir / "boot_a").write_bytes(make_synthetic_boot_v4(stock_ram, kernel=b"KERN" * 256))
    (backup_dir / "boot_b").write_bytes(b"\x00" * 0x200000)
    (backup_dir / "vendor_boot_a").write_bytes(make_synthetic_vendor_boot_v4(b"DTB!" * 512))
    (backup_dir / "vendor_boot_b").write_bytes(b"\x00" * 0x200000)
    (backup_dir / "init_boot_a").write_bytes(make_synthetic_boot_v4(stock_ram, total_size=0x200000))
    (backup_dir / "init_boot_b").write_bytes(b"\x00" * 0x200000)
    (backup_dir / "misc").write_bytes(make_synthetic_misc("_a", total_size=mib))
    (backup_dir / "fulldumpdb").write_bytes(b"\x00" * mib)

    xml_rows = [
        ("sml_a", 1),
        ("trustos_a", 1),
        ("trustos_b", 1),
        ("boot_a", 2),
        ("boot_b", 2),
        ("vendor_boot_a", 2),
        ("vendor_boot_b", 2),
        ("init_boot_a", 2),
        ("init_boot_b", 2),
        ("misc", 1),
        ("fulldumpdb", 1),
    ]
    (backup_dir / "splloader").write_bytes(b"\x00" * 4096)
    (backup_dir / "ztecfg").write_bytes((b"SYNTH_UNIT_A_ZTECFG!" * ((mib // 20) + 1))[:mib])
    xml_rows.append(("ztecfg", 1))
    (backup_dir / "persist").write_bytes((b"SYNTH_UNIT_A_PERSIST!" * ((mib // 21) + 1))[:mib])
    xml_rows.append(("persist", 1))
    (backup_dir / "prodnv").write_bytes((b"SYNTH_UNIT_A_PRODNV!" * ((mib // 20) + 1))[:mib])
    xml_rows.append(("prodnv", 1))
    (backup_dir / "miscdata").write_bytes((b"SYNTH_UNIT_A_MISC!" * ((mib // 18) + 1))[:mib])
    xml_rows.append(("miscdata", 1))
    for core_extra in ("calinv", "super"):
        (backup_dir / core_extra).write_bytes(b"\x00" * mib)
        xml_rows.append((core_extra, 1))

    for src, dst in BSP_SYNC_PAIRS_F50PRO:
        if src == "sml_a":
            (backup_dir / dst).write_bytes((backup_dir / src).read_bytes())
        else:
            (backup_dir / src).write_bytes(b"BSP_" * (mib // 4))
            (backup_dir / dst).write_bytes(b"\x00" * mib)
            xml_rows.append((src, 1))
        xml_rows.append((dst, 1))

    # Resize synthetic sml_a/trustos_a/trustos_b to 1 MiB to match MiB XML table cleanly
    for big_p in ("sml_a", "sml_b", "trustos_a", "trustos_b"):
        raw_p = (backup_dir / big_p).read_bytes()
        (backup_dir / big_p).write_bytes(raw_p.ljust(mib, b"\x00"))

    xml_lines = ['<?xml version="1.0" encoding="utf-8"?>', "<Partitions>"]
    for name, sz_mib in xml_rows:
        xml_lines.append(f'  <Partition id="{name}" size="{sz_mib}"/>')
    xml_lines.append("</Partitions>")
    (backup_dir / "partition_list.xml").write_text("\n".join(xml_lines), encoding="utf-8")

    # 3. Synthetic tools directory (Magisk APK + OpenWrt base payloads)
    apk_dir = tools_dir / "android-pkgs"
    apk_dir.mkdir(parents=True)
    with zipfile.ZipFile(apk_dir / "Magisk-canary-28103.apk", "w") as zf:
        for arc in (
            "lib/arm64-v8a/libmagisk.so",
            "lib/armeabi-v7a/libmagisk.so",
            "lib/arm64-v8a/libbusybox.so",
            "lib/arm64-v8a/libmagiskboot.so",
            "lib/arm64-v8a/libmagiskinit.so",
            "lib/arm64-v8a/libmagiskpolicy.so",
            "lib/arm64-v8a/libinit-ld.so",
            "assets/stub.apk",
            "assets/util_functions.sh",
            "assets/boot_patch.sh",
        ):
            zf.writestr(arc, f"synthetic-{arc}".encode("utf-8"))

    ow_dir = tools_dir / "openwrt-base"
    ow_dir.mkdir(parents=True)
    (ow_dir / "Image-6.12.94-u30pro-p1.wrapped").write_bytes(b"LNX612" * 512)
    (ow_dir / "initramfs-f50pro-generic.cpio.lz4").write_bytes(encode_lz4_legacy_stored(encode_newc_cpio([])))
    (ow_dir / "openwrt-f50pro-25.12.5-base-rootfs.ext4").write_bytes(b"EXT4" * 4096)

    # 4. Valid synthetic 524-byte ADB RSA-2048 public key
    key_bin = bytearray(524)
    struct.pack_into("<I", key_bin, 0, 64)
    key_pub = tmp_path / "adbkey.pub"
    key_pub.write_text(base64.b64encode(bytes(key_bin)).decode("ascii") + " test@synthetic\n", encoding="utf-8")

    return {
        "backup_dir": backup_dir,
        "tools_dir": tools_dir,
        "out_dir": out_dir,
        "adb_pubkey": key_pub,
        "expected_tos_offset": sig_off + 32,
    }
