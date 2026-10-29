#!/usr/bin/env python3
"""Production C/F2FS recovery core with synthetic OpenSSL GCM and hashlib oracles."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import tempfile


def fixture(path, encrypted, root):
    spec = importlib.util.spec_from_file_location("m3_key_fixture", root / "tools/test_fuxi_m3_key_paths.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.build_image(path)
    names = [(".", 6, 2), ("..", 5, 2), ("version", 7, 1),
             ("keymaster_key_blob", 8, 1), ("secdiscardable", 9, 1), ("encrypted_key", 10, 1)]
    directory = bytearray(4096)
    slot = 0
    for name, nid, kind in names:
        raw = name.encode()
        count = (len(raw) + 7) // 8
        for i in range(count):
            directory[(slot + i) // 8] |= 1 << ((slot + i) % 8)
        struct.pack_into("<IHB", directory, 30 + slot * 11 + 4, nid, len(raw), kind)
        directory[30 + 214 * 11 + slot * 8:30 + 214 * 11 + slot * 8 + len(raw)] = raw
        slot += count
    contents = [(8, bytes((i * 3 + 0x42) & 255 for i in range(208)), 4505),
                (9, bytes((i * 7 + 0xA5) & 255 for i in range(16384)), 4506),
                (10, encrypted, 4510)]
    with path.open("r+b") as f:
        f.seek(4503 * 4096)
        f.write(directory)
        for nid, data, first in contents:
            node = bytearray(4096)
            struct.pack_into("<H", node, 0, 0x81A4)
            struct.pack_into("<I", node, 12, 1)
            struct.pack_into("<Q", node, 16, len(data))
            for i in range((len(data) + 4095) // 4096):
                struct.pack_into("<I", node, 360 + 4 * i, first + i)
            struct.pack_into("<III", node, 4072, nid, nid, 0)
            address = 4097 + nid
            f.seek(address * 4096)
            f.write(node)
            f.seek(2560 * 4096 + nid * 9)
            f.write(struct.pack("<BII", 1, nid, address))
            f.seek(first * 4096)
            f.write(data + bytes((-len(data)) % 4096))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--edk2", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, default=Path("/opt/homebrew/opt/openssl@3"))
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    src = root / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe"
    arch = "AArch64" if platform.machine() in ("aarch64", "arm64") else "X64"
    names = ["M3KeyRecovery.c", "M3Secdiscardable.c", "M3KeyRecoveryF2fs.c",
             "DataReadOnly.c", "F2fsReadOnly.c", "F2fsFiles.c"]
    paths = [src / n for n in names]
    paths += [src / n for n in ("M3KeyRecovery.h", "M3KeyRecoveryF2fs.h", "F2fsReadOnly.h", "DataReadOnly.h")]
    paths += [root / "tools/tests/m3_key_recovery_host.c", root / "tools/test_fuxi_m3_key_paths.py", Path(__file__)]
    with tempfile.TemporaryDirectory(prefix="fuxi-recovery-") as tmp:
        temp = Path(tmp)
        binary = temp / "recovery-host"
        command = [shutil.which("clang") or "clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                   "-fshort-wchar", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                   "-I", str(args.edk2 / "MdePkg/Include"),
                   "-I", str(args.edk2 / "MdePkg/Include" / arch), "-I", str(src),
                   "-I", str(args.openssl / "include"), "-L", str(args.openssl / "lib"),
                   "-Wl,-rpath," + str(args.openssl / "lib"),
                   str(root / "tools/tests/m3_key_recovery_host.c"),
                   *(str(src / n) for n in names), "-lcrypto", "-o", str(binary)]
        subprocess.run(command, check=True)
        encrypted = temp / "synthetic-encrypted"
        subprocess.run([str(binary), "--emit", str(encrypted)], check=True)
        image = temp / "metadata.img"
        digest = fixture(image, encrypted.read_bytes(), root)
        samples = [bytes(16384), bytes([255]) * 16384,
                   bytes((i * 7 + 0xA5) & 255 for i in range(16384))]
        prefix = b"Android secdiscardable SHA512".ljust(128, b"\0")
        vectors = temp / "hashlib-vectors"
        vectors.write_bytes(b"".join(hashlib.sha512(prefix + sample).digest() for sample in samples))
        result = subprocess.run([str(binary), str(image), str(vectors)], check=True, capture_output=True, text=True)
        match = re.fullmatch(r"PASS recovery cases=(\d+); synthetic AES-GCM only, no device/KeyMint\n", result.stdout)
        if not match or result.stderr:
            raise ValueError("unexpected host output; no material output permitted")
    report = dict(result="passed", cases=int(match[1]), sanitizers=["address", "undefined"],
                  independent_oracles=["hashlib SHA-512 with 128-byte padded personalization", "OpenSSL AES-256-GCM authentication"],
                  fixture_sha256=digest,
                  scope="Production core and F2FS adapter on synthetic input; no actual KeyMint/SMCI backend, device, SMC, real keys or decryption evidence.",
                  sources={str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"result": "passed", "cases": report["cases"]}, indent=2))


if __name__ == "__main__":
    main()
