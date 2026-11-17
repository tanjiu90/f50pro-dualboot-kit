"""Pure-Python offline builder and parser roundtrip tests across all 3 F50 Pro profiles."""
from __future__ import annotations

import struct
from pathlib import Path

from build_images import build_profile
from common import (
    AVB0_MAGIC,
    AVB_FOOTER_MAGIC,
    PROFILES,
    TRUSTOS_PATCH_OPCODE,
    build_trial_bcab,
    decompress_lz4_legacy,
    parse_avb_footer,
    parse_boot_control,
    parse_newc_cpio,
)
from inspect_backup import inspect_backup_dir


def test_inspect_detects_trustos_offset_dynamically(synthetic_env: dict[str, Path]) -> None:
    """Confirm dynamic signature locator matches arbitrary board offsets (e.g. B15 vs B28)."""
    facts = inspect_backup_dir(synthetic_env["backup_dir"])
    assert facts["trustos_a"]["patch_code_offset"] == synthetic_env["expected_tos_offset"]
    assert facts["init_boot_a"]["sdk"] == "35"
    assert facts["misc"]["suffix"] == "_a"


def test_arm64_dis_avb_ast_locator() -> None:
    """Exercise the pure-Python ARM64 ADRP+ADD+epilogue TrustOS scanner."""
    from inspect_backup import locate_trustos_patch_offset
    from tests.conftest import make_synthetic_dhtb

    # Construct minimal AArch64 function referencing '### enter avb_slot_verify. ###'
    payload = bytearray(0x2000)
    marker = b"### enter avb_slot_verify. ###\x00"
    marker_off = 0x800  # relative to payload start (< 4096 so single ADRP+ADD hits cleanly)
    payload[marker_off : marker_off + len(marker)] = marker

    struct.pack_into("<I", payload, 0x100, 0xA9BE7BFD)  # stp x29, x30, [sp, #-32]!
    struct.pack_into("<I", payload, 0x104, 0x90000000)  # adrp x0, page(0x0)
    struct.pack_into("<I", payload, 0x108, 0x91000000 | (marker_off << 10))
    struct.pack_into("<I", payload, 0x10C, 0x94000010)  # bl (count1)
    struct.pack_into("<I", payload, 0x110, 0xB4000020)  # cbz (count2)
    struct.pack_into("<I", payload, 0x114, 0x94000010)  # bl (count1+count2 == 3 > 2)
    struct.pack_into("<I", payload, 0x118, 0x2A1903FA)  # mov w26, w25 (byte[2]==0x03 at -7)
    struct.pack_into("<I", payload, 0x11C, 0x2A1A03E0)  # mov w0, w26 (0x03e0 at -4)
    for idx in range(5):
        struct.pack_into("<I", payload, 0x120 + idx * 4, 0xA94153F3)  # 5x ldp (byte[3]==0xA9)
    struct.pack_into("<I", payload, 0x138, 0xD65F03C0)  # ret
    struct.pack_into("<I", payload, 0x140, 0xD10003FF)  # next func prologue (scan_hi >= i+32)

    img = make_synthetic_dhtb(bytes(payload), total_size=0x4000)
    res = locate_trustos_patch_offset(img)
    assert res["method"] == "arm64_dis_avb"
    assert res["patch_code_offset"] == 0x11C


def test_bcab_crc_roundtrip() -> None:
    """Validate Android misc+2048 bootloader_control encoding & CRC32 check."""
    stock = bytearray(32)
    stock[:2] = b"_a"
    stock[4:8] = b"BCAB"
    stock[8] = 1
    trial_b = build_trial_bcab(bytes(stock), "b", tries=3)
    parsed = parse_boot_control(b"\x00" * 2048 + trial_b)
    assert parsed["suffix"] == "_b"
    assert parsed["slots"]["b"]["tries_remaining"] == 3
    assert parsed["slots"]["b"]["priority"] == 15


def test_build_profile_1_android_ufi(synthetic_env: dict[str, Path]) -> None:
    """Profile 1 touches only slot _a, stages pure-Python Magisk ramdisk + XZ CRC32 + AVB footer."""
    out_dir = synthetic_env["out_dir"] / "p1"
    plan = build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="1-android-ufi",
        out_dir=out_dir,
        tools_dir=synthetic_env["tools_dir"],
        adb_pubkey_path=synthetic_env["adb_pubkey"],
    )
    parts = [op["partition"] for op in plan["operations"]]
    assert parts == ["trustos_a", "init_boot_a"]
    assert plan["touches_slot_a"] is True
    assert plan["touches_slot_b"] is False

    # Verify patched trustos opcode
    tos = (out_dir / "stage3" / "trustos_noavb.img").read_bytes()
    off = 0x200 + int(synthetic_env["expected_tos_offset"])
    assert tos[off : off + 4] == TRUSTOS_PATCH_OPCODE

    # Verify AVB footer preserved + CPIO overlay + CRC32 XZ
    ib = Path(plan["operations"][1]["file"]).read_bytes()
    assert len(ib) == synthetic_env["backup_dir"].joinpath("init_boot_a").stat().st_size
    footer = parse_avb_footer(ib)
    assert ib[footer["vbmeta_offset"] : footer["vbmeta_offset"] + 4] == AVB0_MAGIC
    assert ib[-64:-60] == AVB_FOOTER_MAGIC

    r_sz = struct.unpack_from("<I", ib, 12)[0]
    entries = {e["name"]: e for e in parse_newc_cpio(decompress_lz4_legacy(ib[4096 : 4096 + r_sz]))}
    assert ".backup/.rmlist" in entries
    assert ".backup/.magisk" in entries
    assert "overlay.d/f50pro-root.rc" in entries
    assert entries[".backup/init.xz"]["data"][:8] == b"\xfd7zXZ\x00\x00\x01"
    assert b"__USB_MODE__" not in entries["overlay.d/sbin/f50pro-root-onboot.sh"]["data"]
    assert b'[ "0" = "1" ]' in entries["overlay.d/sbin/f50pro-test-return-b.sh"]["data"]


def test_build_profile_2_dual_stock_openwrt(synthetic_env: dict[str, Path]) -> None:
    """Profile 2 leaves Android _a untouched and configures OpenWrt _b + sim_mux + trial misc."""
    out_dir = synthetic_env["out_dir"] / "p2"
    plan = build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="2-dual-stock-openwrt",
        out_dir=out_dir,
        tools_dir=synthetic_env["tools_dir"],
    )
    parts = [op["partition"] for op in plan["operations"]]
    assert not any(p.endswith("_a") for p in parts)
    assert "fulldumpdb" in parts
    assert "boot_b" in parts
    assert "vendor_boot_b" in parts
    assert "init_boot_b" in parts
    assert "misc" in parts
    assert plan["android_a_stage"] is None

    vb_b = (out_dir / "stage3" / "vendor_boot_b.6.12.94.img").read_bytes()
    assert b"u30pro_sim_mux.layout=mu3356" in vb_b
    assert b"f50pro_external_power_only=1" in vb_b


def test_build_profile_3_dual_full(synthetic_env: dict[str, Path]) -> None:
    """Profile 3 flashes OpenWrt _b via BROM and stages Android _a for verified OpenWrt application."""
    assert list(PROFILES) == ["1-android-ufi", "2-dual-stock-openwrt", "3-dual-full"]
    out_dir = synthetic_env["out_dir"] / "p3"
    plan = build_profile(
        backup_dir=synthetic_env["backup_dir"],
        profile_id="3-dual-full",
        out_dir=out_dir,
        tools_dir=synthetic_env["tools_dir"],
        adb_pubkey_path=synthetic_env["adb_pubkey"],
    )
    parts = [op["partition"] for op in plan["operations"]]
    assert not any(p.endswith("_a") for p in parts), "BROM step must boot OpenWrt _b cleanly before modifying _a"
    stage = plan["android_a_stage"]
    assert stage and stage["apply_from_openwrt"] is True
    assert stage["usb_mode"] == "charging,adb"

    ib = Path(stage["init_boot_a"]["file"]).read_bytes()
    r_sz = struct.unpack_from("<I", ib, 12)[0]
    entries = {e["name"]: e for e in parse_newc_cpio(decompress_lz4_legacy(ib[4096 : 4096 + r_sz]))}
    assert "overlay.d/sbin/f50pro-known-good-b-bcab.bin" in entries
    assert b'[ "1" = "1" ]' in entries["overlay.d/sbin/f50pro-test-return-b.sh"]["data"]
