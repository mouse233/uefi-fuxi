#!/usr/bin/env python3
"""Build an independent F2FS fixture and exercise the production key-path reads."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile
import zlib


def build_image(path):
    def u16(b, o, v): struct.pack_into('<H', b, o, v)
    def u32(b, o, v): struct.pack_into('<I', b, o, v)
    def u64(b, o, v): struct.pack_into('<Q', b, o, v)
    def crc(b): return zlib.crc32(b, 0xf2f52010 ^ 0xffffffff) ^ 0xffffffff

    def inode(nid, mode, size, address):
        b = bytearray(4096)
        u16(b, 0, mode)
        b[3] = 0
        u32(b, 12, 1)
        u64(b, 16, size)
        u32(b, 360, address)
        u32(b, 4072, nid)
        u32(b, 4076, nid)
        u32(b, 4080, 0)
        return b

    def entries(items):
        b = bytearray(4096)
        position = 0
        for name, nid, kind in items:
            raw = name.encode()
            used = (len(raw) + 7) // 8
            for j in range(used):
                b[(position + j) // 8] |= 1 << ((position + j) % 8)
            u32(b, 30 + position * 11 + 4, nid)
            u16(b, 30 + position * 11 + 8, len(raw))
            b[30 + position * 11 + 10] = kind
            b[30 + 214 * 11 + position * 8:30 + 214 * 11 + position * 8 + len(raw)] = raw
            position += used
        return b

    def nat(b, nid, address):
        offset = (nid % 455) * 9
        b[offset] = 1
        u32(b, offset + 1, nid)
        u32(b, offset + 5, address)

    def checkpoint(version):
        b = bytearray(4096)
        u64(b, 0, version)
        for offset, value in [(132, 1), (136, 8), (140, 1), (156, 64), (160, 64), (164, 4092)]:
            u32(b, offset, value)
        u32(b, 4092, crc(b[:4092]))
        return b

    superblock = bytearray(4096)
    u32(superblock, 1024, 0xf2f52010)
    u16(superblock, 1028, 1)
    for offset, value in [(8, 12), (16, 12), (20, 9), (48, 20), (52, 2), (56, 2), (60, 2),
                          (64, 1), (68, 13), (72, 512), (76, 512), (80, 1536), (84, 2560),
                          (88, 3584), (92, 4096), (96, 3), (100, 1), (104, 2), (2180, 0x499)]:
        u32(superblock, 1024 + offset, value)
    u64(superblock, 1060, 32768)

    blob = bytes((i * 7 + 0xa5) & 0xff for i in range(96))
    blocks = {0: superblock, 1: superblock.copy(), 512: checkpoint(1), 519: checkpoint(1),
              1024: checkpoint(2), 1031: checkpoint(2), 1025: bytearray(4096),
              2560: bytearray(4096)}
    blocks[4100] = inode(3, 0x41ed, 4096, 4500)
    blocks[4101] = inode(4, 0x41ed, 4096, 4501)
    blocks[4102] = inode(5, 0x41ed, 4096, 4502)
    blocks[4103] = inode(6, 0x41ed, 4096, 4503)
    blocks[4104] = inode(7, 0x81a4, 1, 4504)
    blocks[4105] = inode(8, 0x81a4, len(blob), 4505)
    blocks[4500] = entries([('.', 3, 2), ('..', 3, 2), ('vold', 4, 2)])
    blocks[4501] = entries([('.', 4, 2), ('..', 3, 2), ('metadata_encryption', 5, 2)])
    blocks[4502] = entries([('.', 5, 2), ('..', 4, 2), ('key', 6, 2)])
    blocks[4503] = entries([('.', 6, 2), ('..', 5, 2), ('blob', 8, 1), ('version', 7, 1)])
    blocks[4504] = bytearray(b'1' + bytes(4095))
    blocks[4505] = bytearray(blob + bytes(4096 - len(blob)))
    for nid, address in [(3, 4100), (4, 4101), (5, 4102), (6, 4103), (7, 4104), (8, 4105)]:
        nat(blocks[2560], nid, address)
    u16(blocks[1025], 3584, 0)

    image = bytearray(32768 * 4096)
    for lba, block in blocks.items():
        assert lba < 32768 and len(block) == 4096
        image[lba * 4096:(lba + 1) * 4096] = block
    Path(path).write_bytes(bytes(image))
    return hashlib.sha256(bytes(image)).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--edk2', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    src = root / 'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe'
    edk = args.edk2.resolve()
    arch = 'AArch64' if platform.machine() in ('aarch64', 'arm64') else 'X64'
    paths = [src / 'DataReadOnly.c', src / 'DataReadOnly.h', src / 'F2fsReadOnly.c',
             src / 'F2fsReadOnly.h', src / 'F2fsFiles.c',
             root / 'tools/tests/m3_key_paths_host.c', Path(__file__)]
    with tempfile.TemporaryDirectory(prefix='fuxi-m3-key-') as temporary:
        temp = Path(temporary)
        image = temp / 'metadata.img'
        digest = build_image(image)
        binary = temp / 'm3-key-paths'
        command = [shutil.which('clang') or 'clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                   '-fshort-wchar', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                   '-I', str(edk / 'MdePkg/Include'), '-I', str(edk / 'MdePkg/Include' / arch),
                   '-I', str(src), str(root / 'tools/tests/m3_key_paths_host.c'),
                   str(src / 'DataReadOnly.c'), str(src / 'F2fsReadOnly.c'),
                   str(src / 'F2fsFiles.c')]
        subprocess.run([*command, '-o', str(binary)], check=True)
        subprocess.run([str(binary), str(image)], check=True)
    report = {
        'result': 'passed', 'sanitizers': ['address', 'undefined'], 'fixture_sha256': digest,
        'scope': ('production read-only F2FS path lookup/listing on synthetic nested '
                  '/vold/metadata_encryption/key; no device, key use, SMC or decryption'),
        'sources': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in paths},
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
