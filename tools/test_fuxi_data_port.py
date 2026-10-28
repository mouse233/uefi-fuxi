#!/usr/bin/env python3
"""ASan/UBSan tests of production readers; fixture CRCs use Python zlib."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import random
import shutil
import struct
import subprocess
import tempfile
import zlib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--edk2", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = root / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe"
    edk = args.edk2.resolve()
    machine = "AArch64" if platform.machine() in ("arm64", "aarch64") else "X64"
    cases = []
    error = lambda number: (1 << 63) | number

    def disk(block):
        image = bytearray(block * 256)
        header = memoryview(image)[block:2 * block]
        header[:8] = b"EFI PART"
        struct.pack_into("<IIIIQQQQ", header, 8, 0x10000, 92, 0, 0, 1, 255, 8, 247)
        header[56:72] = bytes(range(1, 17))
        struct.pack_into("<QIII", header, 72, 2, 16, 128, 0)
        for index, (name, first, last) in enumerate((("metadata", 8, 31), ("userdata", 32, 240))):
            offset = 2 * block + 128 * index
            image[offset:offset + 16] = bytes(range(1, 17))
            image[offset + 16:offset + 32] = bytes([index + 1]) * 16
            struct.pack_into("<QQ", image, offset + 32, first, last)
            encoded = name.encode("utf-16-le")
            image[offset + 56:offset + 56 + len(encoded)] = encoded
        return image

    def checksums(image, block):
        struct.pack_into("<I", image, block + 88, zlib.crc32(image[2 * block:2 * block + 2048]))
        struct.pack_into("<I", image, block + 16, 0)
        struct.pack_into("<I", image, block + 16, zlib.crc32(image[block:block + 92]))

    for block in (512, 4096):
        original = disk(block)
        checksums(original, block)
        cases.append((f"valid-{block}", block, original, 0))
        both = original.copy()
        for index, name, first, last in ((2, "keymaster_a", 241, 243), (3, "keymaster_b", 244, 246)):
            pos = 2 * block + 128 * index
            both[pos:pos+16] = bytes(range(1, 17))
            both[pos+16:pos+32] = bytes([index+1]) * 16
            struct.pack_into("<QQ", both, pos+32, first, last)
            encoded = name.encode("utf-16-le")
            both[pos+56:pos+56+len(encoded)] = encoded
        checksums(both, block)
        cases.append((f"keymaster-both-{block}", block, both, 0))
        duplicate = both.copy()
        pos = 2 * block + 128 * 3 + 56
        duplicate[pos:pos+72] = bytes(72)
        duplicate[pos:pos+len("keymaster_a".encode("utf-16-le"))] = "keymaster_a".encode("utf-16-le")
        checksums(duplicate, block)
        cases.append((f"keymaster-duplicate-{block}", block, duplicate, error(10)))
        for label, offset, data, expected, recalc in (
            ("bad-header-crc", block + 16, b"\0" * 4, error(27), False),
            ("bad-array-crc", 2 * block + 56, b"X", error(27), False),
            ("overlap", 2 * block + 128 + 32, struct.pack("<Q", 20), error(10), True),
            ("duplicate-guid", 2 * block + 128 + 16, bytes([1]) * 16, error(10), True),
            ("outside-partition", 2 * block + 40, struct.pack("<Q", 255), error(10), True),
            ("duplicate-name", 2 * block + 128 + 56, "metadata".encode("utf-16-le"), error(10), True),
            ("array-overflow", block + 72, struct.pack("<Q", (1 << 64) - 1), error(10), True),
            ("bad-backup", block + 32, struct.pack("<Q", 200), error(10), True),
            ("zero-disk-guid", block + 56, bytes(16), error(10), True),
            ("zero-part-guid", 2 * block + 16, bytes(16), error(10), True),
            ("unsupported-count", block + 80, struct.pack("<I", 129), error(3), True),
        ):
            image = original.copy()
            image[offset:offset + len(data)] = data
            if recalc:
                checksums(image, block)
            cases.append((f"{label}-{block}", block, image, expected))
        # Random corruption inside the entry-array name field must fail CRC.
        rng = random.Random(block)
        for index in range(24):
            image = original.copy()
            image[2 * block + 56 + rng.randrange(72)] ^= rng.randrange(1, 256)
            cases.append((f"corrupt-{block}-{index}", block, image, error(27)))

    # Linux v5.15's packed on-disk schema, encoded independently of C types.
    first4k = bytearray(4096)
    struct.pack_into("<IHHIIII", first4k, 1024, 0xf2f52010, 1, 15, 12, 0, 12, 9)
    struct.pack_into("<Q", first4k, 1024 + 36, 4096)
    for offset, value in ((76, 2), (80, 1026), (84, 1538), (88, 2050),
                          (92, 2562), (96, 3), (100, 1), (104, 2)):
        struct.pack_into("<I", first4k, 1024 + offset, value)
    cases.append(("f2fs-header", "f2fs", first4k, 0))
    for label, offset, fmt, value, expected in (
        ("ciphertext", 0, "I", 0x7086bec0, error(14)),
        ("unsupported-block", 16, "I", 13, error(3)),
        ("huge-sector", 8, "I", 0xffffffff, error(3)),
        ("partition-overrun", 36, "Q", 4097, error(10)),
        ("blocks-overflow", 36, "Q", (1 << 64) - 1, error(10)),
        ("nat-outside", 84, "I", 0xffffffff, error(10)),
        ("main-outside", 92, "I", 4096, error(10)),
        ("bad-root", 96, "I", 1, error(10)),
    ):
        image = first4k.copy()
        struct.pack_into("<" + fmt, image, 1024 + offset, value)
        cases.append((label, "f2fs", image, expected))
    cases.append(("short-f2fs", "f2fs", first4k[:4095], error(2)))

    command = [shutil.which("clang") or "clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
               "-fshort-wchar", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
               "-I", str(edk / "MdePkg/Include"), "-I", str(edk / "MdePkg/Include" / machine),
               "-I", str(source), str(root / "tools/tests/fuxi_data_host.c"), str(source / "DataReadOnly.c")]
    with tempfile.TemporaryDirectory(prefix="fuxi-data-test-") as temporary:
        temp = Path(temporary)
        binary = temp / "host-tests"
        subprocess.run([*command, "-o", str(binary)], check=True)
        for name, block, image, expected in cases:
            path = temp / "disk.bin"
            path.write_bytes(image)
            subprocess.run([str(binary), str(path), str(block), hex(expected)], check=True)
    report = dict(result="passed", fixture_cases=len(cases), sanitizers=["address", "undefined"],
                  scope="production GPT/bounds/F2FS-header/SCM query construction; no device or SMC execution",
                  sources={str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in [source / "DataReadOnly.c", source / "DataReadOnly.h",
                                     root / "tools/tests/fuxi_data_host.c", Path(__file__)]})
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
