"""Pure-Python offline builder for all 3 F50 Pro flashing profiles (no WSL required)."""
from __future__ import annotations

import argparse
import base64
import hashlib
import shutil
import struct
import zipfile
from pathlib import Path
from typing import Any

from common import (
    ASSETS_DIR,
    BSP_SYNC_PAIRS_F50PRO,
    DEFAULT_TOOLS_DIR,
    F50PRO_VENDOR_BOOT_EXTRA_ARGS,
    FORBIDDEN_PARTITIONS,
    MISC_BC_OFFSET,
    PROFILES,
    REPO_ROOT,
    TRUSTOS_ORIG_OPCODE,
    TRUSTOS_PATCH_OPCODE,
    build_trial_bcab,
    decompress_lz4_legacy,
    dhtb_data_size,
    encode_lz4_legacy_stored,
    encode_newc_cpio,
    parse_avb_footer,
    parse_dhtb_header,
    parse_newc_cpio,
    parse_simghdr,
    repack_boot_v4_with_avb,
    repack_vendor_boot_v4,
    sha256_bytes,
    sha256_file,
    write_json,
    xz_compress_crc32,
)
from inspect_backup import inspect_backup_dir

MAGISK_ENV_SOURCES = {
    "magisk": ("lib/arm64-v8a/libmagisk.so", "0755"),
    "magisk32": ("lib/armeabi-v7a/libmagisk.so", "0755"),
    "busybox": ("lib/arm64-v8a/libbusybox.so", "0755"),
    "magiskboot": ("lib/arm64-v8a/libmagiskboot.so", "0755"),
    "magiskinit": ("lib/arm64-v8a/libmagiskinit.so", "0755"),
    "magiskpolicy": ("lib/arm64-v8a/libmagiskpolicy.so", "0755"),
    "init-ld": ("lib/arm64-v8a/libinit-ld.so", "0755"),
    "stub.apk": ("assets/stub.apk", "0644"),
    "util_functions.sh": ("assets/util_functions.sh", "0755"),
    "boot_patch.sh": ("assets/boot_patch.sh", "0755"),
}


def validate_adb_pubkey(pub_path: Path) -> tuple[str, str]:
    """Validate RSA-2048 ADB public key line and return (line, sha256)."""
    line = pub_path.read_text(encoding="utf-8").strip()
    if "\n" in line or not line:
        raise ValueError(f"Expected single-line ADB public key: {pub_path}")
    decoded = base64.b64decode(line.split()[0], validate=True)
    if len(decoded) != 524 or struct.unpack_from("<I", decoded)[0] != 64:
        raise ValueError("Invalid RSA-2048 ADB public key binary structure")
    return line, sha256_bytes(decoded)


def derive_own_trustos_noavb(
    sml_bytes: bytes,
    tos_bytes: bytes,
    patch_code_offset: int,
    *,
    pad_to_size: int | None = None,
) -> bytes:
    """Wrap this device's patched trustos code with its own trimmed signed sml header/trailer."""
    sml_trim = sml_bytes[: dhtb_data_size(sml_bytes)]
    tos_trim = tos_bytes[: dhtb_data_size(tos_bytes)]
    sml_dhtb = parse_dhtb_header(sml_trim)
    parse_simghdr(sml_trim, trailer_offset=sml_dhtb["trailer_offset"])
    tos_dhtb = parse_dhtb_header(tos_trim)
    parse_simghdr(tos_trim, trailer_offset=tos_dhtb["trailer_offset"])

    tos_pay_sz = tos_dhtb["payload_sz"]
    tos_code = bytearray(tos_trim[0x200 : 0x200 + tos_pay_sz])
    if tos_code[patch_code_offset : patch_code_offset + 4] != TRUSTOS_ORIG_OPCODE:
        raise ValueError(f"Unexpected instruction at 0x{patch_code_offset:x}")
    tos_code[patch_code_offset : patch_code_offset + 4] = TRUSTOS_PATCH_OPCODE

    hdr = bytearray(sml_trim[:0x200])
    old_img_sz = struct.unpack_from("<I", hdr, 0x30)[0]
    struct.pack_into("<I", hdr, 0x30, old_img_sz + tos_pay_sz)

    sml_rest = bytearray(sml_trim[0x200:])
    tr_rel = sml_dhtb["trailer_offset"] - 0x200
    for field_off in (0x18, 0x28):
        val = struct.unpack_from("<Q", sml_rest, tr_rel + field_off)[0]
        struct.pack_into("<Q", sml_rest, tr_rel + field_off, val + tos_pay_sz)

    wrapped = bytes(hdr) + bytes(tos_code) + bytes(sml_rest)
    if pad_to_size is not None:
        if len(wrapped) > pad_to_size:
            raise ValueError(f"Derived trustos ({len(wrapped)} B) exceeds partition capacity ({pad_to_size} B)")
        wrapped = wrapped.ljust(pad_to_size, b"\x00")
    return wrapped


def _render_template(path: Path, replacements: dict[str, str]) -> bytes:
    text = path.read_text(encoding="utf-8")
    for k, v in replacements.items():
        text = text.replace(k, v)
    return text.replace("\r\n", "\n").encode("utf-8")


def build_magisk_init_boot_pure_python(
    *,
    stock_init_boot: bytes,
    magisk_apk_path: Path,
    adb_key_line: str,
    known_good_b_bcab: bytes | None,
    usb_mode: str,
    enable_return_b_timer: bool,
    env_dir: Path,
) -> tuple[bytes, dict[str, Any]]:
    """Patch init_boot_a with Magisk 28103 overlay cleanly using stdlib Python + AVB0 preservation."""
    page = 4096
    k_sz = struct.unpack_from("<I", stock_init_boot, 8)[0]
    r_sz = struct.unpack_from("<I", stock_init_boot, 12)[0]
    r_off = page + ((k_sz + page - 1) // page) * page
    stock_cpio_raw = decompress_lz4_legacy(stock_init_boot[r_off : r_off + r_sz])
    stock_entries = parse_newc_cpio(stock_cpio_raw)
    dedup = {e["name"]: dict(e) for e in stock_entries}
    stock_init_bytes = dedup["init"]["data"]
    stock_sha1 = hashlib.sha1(stock_init_boot).hexdigest()

    env_dir.mkdir(parents=True, exist_ok=True)
    env_files = []
    with zipfile.ZipFile(magisk_apk_path) as apk:
        for dst_name, (arc_name, mode) in MAGISK_ENV_SOURCES.items():
            raw = apk.read(arc_name)
            (env_dir / dst_name).write_bytes(raw)
            env_files.append({"name": dst_name, "mode": mode, "bytes": len(raw), "sha256": sha256_bytes(raw)})
        magiskinit = apk.read("lib/arm64-v8a/libmagiskinit.so")
        magisk_bin = apk.read("lib/arm64-v8a/libmagisk.so")
        init_ld = apk.read("lib/arm64-v8a/libinit-ld.so")
        stub = apk.read("assets/stub.apk")
    write_json(env_dir / "manifest.json", {"magisk_version": "1e3edb88 (28103)", "files": env_files})

    scripts_dir = ASSETS_DIR / "android-scripts"
    rc_bytes = _render_template(scripts_dir / "overlay-root.rc", {})
    onboot_bytes = _render_template(scripts_dir / "overlay-onboot.sh.tpl", {"__USB_MODE__": usb_mode})
    return_b_bytes = _render_template(
        scripts_dir / "overlay-return-b.sh.tpl",
        {"__ENABLE_RETURN_B_TIMER__": "1" if enable_return_b_timer else "0"},
    )

    new_items = [
        {"name": "overlay.d", "mode": 0o040750, "data": b""},
        {"name": "overlay.d/f50pro-root.rc", "mode": 0o100644, "data": rc_bytes},
        {"name": "overlay.d/sbin", "mode": 0o040750, "data": b""},
        {"name": "overlay.d/sbin/f50pro-adb-authorized-key.pub", "mode": 0o100644, "data": (adb_key_line + "\n").encode("utf-8")},
        {"name": "overlay.d/sbin/f50pro-root-onboot.sh", "mode": 0o100755, "data": onboot_bytes},
        {"name": "overlay.d/sbin/f50pro-test-return-b.sh", "mode": 0o100755, "data": return_b_bytes},
        {"name": "overlay.d/sbin/init-ld.xz", "mode": 0o100644, "data": xz_compress_crc32(init_ld)},
        {"name": "overlay.d/sbin/magisk.xz", "mode": 0o100644, "data": xz_compress_crc32(magisk_bin)},
        {"name": "overlay.d/sbin/stub.xz", "mode": 0o100644, "data": xz_compress_crc32(stub)},
    ]
    if known_good_b_bcab is not None:
        new_items.insert(
            4,
            {"name": "overlay.d/sbin/f50pro-known-good-b-bcab.bin", "mode": 0o100644, "data": known_good_b_bcab},
        )

    rmlist = b"\x00".join(item["name"].encode("utf-8") for item in new_items) + b"\x00"
    cfg = (
        "KEEPVERITY=true\nKEEPFORCEENCRYPT=true\nRECOVERYMODE=false\n"
        f"PREINITDEVICE=metadata\nSHA1={stock_sha1}\n"
    ).encode("utf-8")

    merged = list(dedup.values())
    for item in merged:
        if item["name"] == "init":
            item["mode"] = 0o100750
            item["data"] = magiskinit
    merged.extend(new_items)
    merged.extend([
        {"name": ".backup", "mode": 0o040000, "data": b""},
        {"name": ".backup/.magisk", "mode": 0o100000, "data": cfg},
        {"name": ".backup/.rmlist", "mode": 0o100000, "data": rmlist},
        {"name": ".backup/init.xz", "mode": 0o100750, "data": xz_compress_crc32(stock_init_bytes)},
    ])

    cpio_bytes = encode_newc_cpio(merged)
    lz4_bytes = encode_lz4_legacy_stored(cpio_bytes)
    candidate, meta = repack_boot_v4_with_avb(stock_init_boot, ramdisk=lz4_bytes)
    # Roundtrip sanity check of footer & CPIO
    parse_avb_footer(candidate)
    meta["entry_count"] = len(merged)
    return candidate, meta


def _op(part: str, file_path: Path, method: str = "w", offset: int = 0) -> dict[str, Any]:
    if part in FORBIDDEN_PARTITIONS:
        raise ValueError(f"Refusing to add forbidden partition to plan: {part}")
    sz = file_path.stat().st_size
    item: dict[str, Any] = {
        "op": method,
        "partition": part,
        "file": str(file_path),
        "size_bytes": sz,
        "sha256": sha256_file(file_path),
    }
    if offset:
        item["offset"] = offset
    return item


def build_profile(
    *,
    backup_dir: Path,
    profile_id: str,
    out_dir: Path,
    tools_dir: Path = DEFAULT_TOOLS_DIR,
    adb_pubkey_path: Path | None = None,
    usb_mode: str | None = None,
) -> dict[str, Any]:
    """Assemble offline images and strict flash_plan.json for the selected profile."""
    if profile_id not in PROFILES:
        raise ValueError(f"Unknown profile {profile_id!r}; expected one of {list(PROFILES)}")
    profile = PROFILES[profile_id]
    hw = inspect_backup_dir(backup_dir, out_dir / "hardware_facts.json")

    stage3 = out_dir / "stage3"
    stage3.mkdir(parents=True, exist_ok=True)
    ops: list[dict[str, Any]] = []
    android_stage: dict[str, Any] | None = None

    sml_a = (backup_dir / "sml_a").read_bytes()
    tos_a = (backup_dir / "trustos_a").read_bytes()
    tos_cap = (backup_dir / "trustos_b").stat().st_size
    tos_noavb = derive_own_trustos_noavb(
        sml_a, tos_a, hw["trustos_a"]["patch_code_offset"], pad_to_size=tos_cap
    )
    tos_path = stage3 / "trustos_noavb.img"
    tos_path.write_bytes(tos_noavb)

    if profile["openwrt"]:
        owrt_pack = tools_dir / "openwrt-base"
        k_path = owrt_pack / "Image-6.12.94-u30pro-p1.wrapped"
        ram_path = owrt_pack / "initramfs-f50pro-generic.cpio.lz4"
        rootfs_path = owrt_pack / "openwrt-f50pro-25.12.5-base-rootfs.ext4"
        for req in (k_path, ram_path, rootfs_path):
            if not req.is_file():
                raise FileNotFoundError(f"Missing OpenWrt base asset: {req}. Run fetch_assets.py first.")

        for src_p, dst_p in BSP_SYNC_PAIRS_F50PRO:
            sf = backup_dir / src_p
            df = backup_dir / dst_p
            if not sf.is_file() or not df.is_file():
                raise FileNotFoundError(f"Missing BSP pair {src_p} -> {dst_p} in backup")
            if sf.stat().st_size == 0 or sf.stat().st_size > df.stat().st_size:
                raise ValueError(
                    f"Source {src_p} ({sf.stat().st_size} B) exceeds target {dst_p} capacity ({df.stat().st_size} B)"
                )
            ops.append(_op(dst_p, sf))

        ops.append(_op("trustos_b", tos_path))

        boot_b, _ = repack_boot_v4_with_avb(
            (backup_dir / "boot_a").read_bytes(),
            kernel=k_path.read_bytes(),
            ramdisk=ram_path.read_bytes(),
        )
        hdr_b = bytearray(boot_b)
        hdr_b[44:1580] = b"loglevel=5\x00".ljust(1536, b"\x00")
        struct.pack_into("<I", hdr_b, 1580, 0)
        boot_b_path = stage3 / "boot_b.6.12.94.img"
        boot_b_path.write_bytes(bytes(hdr_b))
        ops.append(_op("boot_b", boot_b_path))

        vb_b, _ = repack_vendor_boot_v4(
            (backup_dir / "vendor_boot_a").read_bytes(),
            F50PRO_VENDOR_BOOT_EXTRA_ARGS,
            expected_dtb_sha256=hw["vendor_boot_a"]["dtb_sha256"],
            ramdisk=ram_path.read_bytes(),
        )
        vb_b_path = stage3 / "vendor_boot_b.6.12.94.img"
        vb_b_path.write_bytes(vb_b)
        ops.append(_op("vendor_boot_b", vb_b_path))

        ops.append(_op("fulldumpdb", rootfs_path))

        empty_ram = encode_lz4_legacy_stored(encode_newc_cpio([]))
        ib_b, _ = repack_boot_v4_with_avb((backup_dir / "init_boot_a").read_bytes(), ramdisk=empty_ram)
        ib_b_path = stage3 / "init_boot_b.img"
        ib_b_path.write_bytes(ib_b)
        ops.append(_op("init_boot_b", ib_b_path, method="w_force"))

        misc_live = (backup_dir / "misc").read_bytes()[MISC_BC_OFFSET : MISC_BC_OFFSET + 32]
        trial_b = build_trial_bcab(misc_live, "b", tries=3)
        trial_b_path = stage3 / "misc_trial_b.bin"
        trial_b_path.write_bytes(trial_b)
        (stage3 / "misc_rollback_a.bin").write_bytes(misc_live)
        ops.append(_op("misc", trial_b_path, method="wof", offset=MISC_BC_OFFSET))

    if profile["android_root"]:
        apk_path = tools_dir / "android-pkgs" / "Magisk-canary-28103.apk"
        if not apk_path.is_file():
            raise FileNotFoundError(f"Missing {apk_path}; run fetch_assets.py first.")
        if adb_pubkey_path is None:
            adb_pubkey_path = Path.home() / ".android" / "adbkey.pub"
        key_line, key_sha = validate_adb_pubkey(adb_pubkey_path)
        chosen_usb = usb_mode or profile["default_usb_mode"] or "charging,adb"

        # Compute expected good OpenWrt _b BCAB block if OpenWrt is part of this profile
        known_b_bcab: bytes | None = None
        if profile["openwrt"]:
            # Live OpenWrt sets successful=1, tries=6, priority=15 for slot b (raw 0xef or 0x6f? note misc-bc-slot-b has successful=0x80)
            # We pre-seed trial _b here, and provision_android uses live runtime /run or misc+2048 read from OpenWrt!
            misc_live = (backup_dir / "misc").read_bytes()[MISC_BC_OFFSET : MISC_BC_OFFSET + 32]
            known_b_bcab = build_trial_bcab(misc_live, "b", tries=6)
            known_b_path = stage3 / "known-good-b-bcab.bin"
            known_b_path.write_bytes(known_b_bcab)

        magisk_dir = stage3 / "magisk-a"
        cand_ib, ib_meta = build_magisk_init_boot_pure_python(
            stock_init_boot=(backup_dir / "init_boot_a").read_bytes(),
            magisk_apk_path=apk_path,
            adb_key_line=key_line,
            known_good_b_bcab=known_b_bcab,
            usb_mode=chosen_usb,
            enable_return_b_timer=bool(profile["openwrt"]),
            env_dir=magisk_dir / "magisk-env",
        )
        ib_a_path = magisk_dir / "init_boot_a.magisk-28103.img"
        ib_a_path.write_bytes(cand_ib)

        if profile_id == "1-android-ufi":
            # Profile 1 touches ONLY Android _a directly via BROM spd_dump
            ops.append(_op("trustos_a", tos_path))
            ops.append(_op("init_boot_a", ib_a_path))
        else:
            # Profile 3 boots OpenWrt _b first via BROM, then safely writes _a from OpenWrt root
            android_stage = {
                "apply_from_openwrt": True,
                "usb_mode": chosen_usb,
                "adb_pubkey_sha256": key_sha,
                "trustos_a": {
                    "file": str(tos_path),
                    "size_bytes": len(tos_noavb),
                    "sha256": sha256_bytes(tos_noavb),
                    "expected_stock_first_bytes": (backup_dir / "trustos_a").stat().st_size,
                    "expected_stock_sha256": sha256_file(backup_dir / "trustos_a"),
                },
                "init_boot_a": {
                    "file": str(ib_a_path),
                    "size_bytes": len(cand_ib),
                    "sha256": sha256_bytes(cand_ib),
                    "expected_stock_sha256": sha256_file(backup_dir / "init_boot_a"),
                    "meta": ib_meta,
                },
            }

    plan = {
        "profile": profile_id,
        "profile_name": profile["name"],
        "backup_dir": str(backup_dir),
        "out_dir": str(out_dir),
        "touches_slot_a": profile["touches_slot_a"],
        "touches_slot_b": profile["touches_slot_b"],
        "operations": ops,
        "total_brom_write_bytes": sum(o["size_bytes"] for o in ops),
        "android_a_stage": android_stage,
    }
    write_json(out_dir / "flash_plan.json", plan)
    return plan


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-dir", type=Path, required=True)
    parser.add_argument("--profile", required=True, choices=list(PROFILES))
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--tools-dir", type=Path, default=DEFAULT_TOOLS_DIR)
    parser.add_argument("--adb-pubkey", type=Path)
    parser.add_argument("--usb-mode", help="Android USB mode override (e.g. charging,adb or rndis,serial_smd,diag,adb)")
    args = parser.parse_args()

    bdir = args.backup_dir if args.backup_dir.is_absolute() else (REPO_ROOT / args.backup_dir)
    odir = args.out_dir if args.out_dir.is_absolute() else (REPO_ROOT / args.out_dir)
    plan = build_profile(
        backup_dir=bdir,
        profile_id=args.profile,
        out_dir=odir,
        tools_dir=args.tools_dir,
        adb_pubkey_path=args.adb_pubkey,
        usb_mode=args.usb_mode,
    )
    print(f"Built profile {args.profile}: {len(plan['operations'])} BROM ops ({plan['total_brom_write_bytes'] / (1024*1024):.2f} MiB) -> {odir / 'flash_plan.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
