#!/usr/bin/env python3
"""Bind this port's interface evidence to the exact user-supplied TWRP image.

No image code is executed. Only whitelisted files are passed to the host ELF
reader; proprietary files remain temporary and are not copied into the repo.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import tempfile

IMAGE_SHA = "68f3829ba4b7faaf8b873fd0dce7dabd03b2bdd750debbae56b1dbe326f87da5"
CPIO_SHA = "6973560a73525ae1bbf2c13102934067d45cac2344e93ca077b9d0097923ba93"
FILES = [
    "prop.default", "init.recovery.qcom.rc", "system/etc/recovery.fstab",
    "system/etc/twrp.flags", "system/bin/recovery",
    "vendor/bin/hw/android.hardware.security.keymint-service-qti",
    "vendor/lib64/libqtikeymint.so", "vendor/lib64/libminkdescriptor.so",
    "vendor/lib/modules/1.1/ufs_qcom.ko", "vendor/lib/modules/1.1/ufshcd-crypto-qti.ko",
    "vendor/lib/modules/1.1/crypto-qti-common.ko", "vendor/lib/modules/1.1/crypto-qti-hwkm.ko",
    "vendor/lib/modules/1.1/qcom-scm.ko",
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--readelf", default=shutil.which("llvm-readelf") or
                        "/opt/homebrew/opt/llvm/bin/llvm-readelf")
    args = parser.parse_args()
    image = args.image.read_bytes()
    if sha(image) != IMAGE_SHA:
        raise SystemExit("Image differs from the audited skkk v9.0 input; audit before changing pins")
    if image[:8] != b"ANDROID!" or struct.unpack_from("<I", image, 40)[0] != 4:
        raise SystemExit("Unexpected image header")
    size = struct.unpack_from("<I", image, 12)[0]
    if struct.unpack_from("<I", image, 8)[0] != 0 or 4096 + size > len(image):
        raise SystemExit("Unexpected kernel/ramdisk layout")
    selected = {}
    with tempfile.TemporaryDirectory(prefix="fuxi-twrp-audit-") as temporary:
        temp = Path(temporary)
        compressed = temp / "ramdisk.lz4"
        cpio = temp / "ramdisk.cpio"
        compressed.write_bytes(image[4096:4096 + size])
        subprocess.run([shutil.which("lz4") or "lz4", "-d", str(compressed), str(cpio)], check=True)
        if cpio.stat().st_size > 256 * 1024 * 1024:
            raise SystemExit("Unexpected ramdisk expansion")
        archive = cpio.read_bytes()
        if sha(archive) != CPIO_SHA:
            raise SystemExit("CPIO does not match the audited input")
        position = 0
        while True:
            if position + 110 > len(archive) or archive[position:position + 6] != b"070701":
                raise SystemExit("Invalid newc header")
            fields = [int(archive[position + 6 + i * 8:position + 14 + i * 8], 16) for i in range(13)]
            mode, count, name_bytes = fields[1], fields[6], fields[11]
            end_name = position + 110 + name_bytes
            if name_bytes == 0 or end_name > len(archive) or archive[end_name - 1] != 0:
                raise SystemExit("Invalid newc name")
            name = archive[position + 110:end_name - 1].decode()
            start = (end_name + 3) & ~3
            if start + count > len(archive):
                raise SystemExit("Truncated newc entry")
            content = archive[start:start + count]
            position = (start + count + 3) & ~3
            if name == "TRAILER!!!":
                if any(archive[position:]):
                    raise SystemExit("Unexpected second archive")
                break
            if name not in FILES:
                continue
            if name in selected or not stat.S_ISREG(mode):
                raise SystemExit("Duplicate/nonregular evidence entry")
            record = dict(bytes=len(content), sha256=sha(content))
            if content[:4] == b"\x7fELF":
                path = temp / "selected.elf"
                path.write_bytes(content)
                elf = subprocess.check_output([args.readelf, "-d", "-sW", str(path)], text=True)
                record["needed"] = re.findall(r"Shared library: \[(.*?)\]", elf)
                record["interface_symbols"] = sorted(set(
                    line.split()[-1] for line in elf.splitlines()
                    if re.search(r"\b(Decrypt_DE|Decrypt_User|crypto_qti_[A-Za-z_]+|qcom_scm_[A-Za-z_]*ice_key|qcom_scm_derive_raw_secret)\b", line)
                ))
                strings = [match.group().decode() for match in re.finditer(rb"[\x20-\x7e]{6,}", content)]
                record["module_abi"] = [s for s in strings if s.startswith(("vermagic=", "depends="))]
            selected[name] = record
    if set(selected) != set(FILES):
        raise SystemExit("Missing evidence files")
    report = dict(schema=1, image_name=args.image.name, image_sha256=IMAGE_SHA,
                  cpio_sha256=CPIO_SHA, files=selected,
                  scope="static interface evidence; no decryption, SMC, or device execution")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"Bound {len(selected)} files to {IMAGE_SHA}; report: {args.output}")


if __name__ == "__main__":
    main()
