#!/usr/bin/env python3
"""Replace only the ramdisk of a v3 fuxi diagnostic boot image, offline."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def package(boot_path, payload_path, output):
    boot, payload = boot_path.read_bytes(), payload_path.read_bytes()
    if boot[:8] != b"ANDROID!" or struct.unpack_from("<I", boot, 40)[0] != 3:
        raise ValueError("expected Android boot header v3")
    kernel_size, ramdisk_size, version, header_size = struct.unpack_from("<IIII", boot, 8)
    if header_size != 1580 or version != 0x220001A7:
        raise ValueError("unexpected header/OS metadata; recheck the stock boot header")
    if len(payload) != 4194304 or payload[3:11] != b"FUXIPAYL":
        raise ValueError("expected identified 4 MiB diagnostic FAT")
    offset = 4096 + ((kernel_size + 4095) // 4096) * 4096
    if len(boot) != offset + ((ramdisk_size + 4095) // 4096) * 4096:
        raise ValueError("unexpected trailing data; not discarding an unknown footer")
    if boot[offset:offset + ramdisk_size] != b"dummy":
        raise ValueError("expected a newly built dummy-ramdisk firmware image")
    packed = bytearray(boot[:offset])
    struct.pack_into("<I", packed, 12, len(payload))
    packed.extend(payload)
    packed.extend(b"\0" * (-len(packed) % 4096))
    assert packed[:12] == boot[:12] and packed[16:offset] == boot[16:offset]
    if output.exists():
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(packed)
    digest = lambda data: hashlib.sha256(data).hexdigest()
    manifest = {"bytes": len(packed), "sha256": digest(packed), "input_boot_sha256": digest(boot),
                "payload_sha256": digest(payload), "header_version": 3, "os_version_raw": hex(version),
                "kernel_sha256": digest(boot[4096:4096 + kernel_size]),
                "ramdisk_bytes": len(payload), "ramdisk_offset": offset,
                "preserved": "kernel (shim, FD, appended DTB) and all other header fields",
                "device_test": "not yet boot-tested"}
    output.with_suffix(".json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--boot", type=Path, required=True)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    package(args.boot, args.payload, args.output)
