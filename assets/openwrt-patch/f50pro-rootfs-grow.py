#!/usr/bin/python3
"""Grow only the verified F50 Pro 2 GiB fulldumpdb filesystem through ext4's online API."""
import fcntl
import json
import os
import pathlib
import struct

root = pathlib.Path('/sys/class/block/mmcblk0p62')
if pathlib.Path('/etc/mu300/model').read_text().strip() != 'f50pro':
    raise SystemExit(0)
if 'PARTNAME=fulldumpdb' not in (root / 'uevent').read_text():
    raise SystemExit('Rootfs growth rejected: unexpected partition')
target = int((root / 'size').read_text()) * 512
if target != 2147483648:
    raise SystemExit('Rootfs growth rejected: unexpected partition capacity')
if os.stat('/').st_dev != os.stat('/dev/mmcblk0p62').st_rdev:
    raise SystemExit('Rootfs growth rejected: mounted root belongs to another device')
with open('/dev/mmcblk0p62', 'rb') as stream:
    stream.seek(1024)
    superblock = stream.read(1024)
if struct.unpack_from('<H', superblock, 56)[0] != 0xef53:
    raise SystemExit('Rootfs growth rejected: expected ext4')
block_size = 1024 << struct.unpack_from('<I', superblock, 24)[0]
blocks = struct.unpack_from('<I', superblock, 4)[0]
if struct.unpack_from('<I', superblock, 96)[0] & 0x80:
    blocks += struct.unpack_from('<I', superblock, 336)[0] << 32
if blocks * block_size > target:
    raise SystemExit('Rootfs growth rejected: filesystem exceeds partition')
if blocks * block_size < target:
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        # EXT4_IOC_RESIZE_FS = _IOW('f', 16, __u64), the normal online resize API.
        fcntl.ioctl(descriptor, (1 << 30) | (8 << 16) | (ord('f') << 8) | 16,
                    struct.pack('=Q', target // block_size))
    finally:
        os.close(descriptor)
    with open('/dev/mmcblk0p62', 'rb') as stream:
        stream.seek(1024)
        observed = stream.read(1024)
    observed_blocks = struct.unpack_from('<I', observed, 4)[0]
    if struct.unpack_from('<I', observed, 96)[0] & 0x80:
        observed_blocks += struct.unpack_from('<I', observed, 336)[0] << 32
    if observed_blocks * block_size != target:
        raise SystemExit('Rootfs growth failed its filesystem-size readback')
result = {'filesystem_bytes': target, 'already_full': blocks * block_size == target}
pathlib.Path('/run/f50pro-rootfs-capacity.json').write_text(json.dumps(result))
print(json.dumps(result))
