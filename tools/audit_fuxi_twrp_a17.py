#!/usr/bin/env python3
"""Offline, bounded inspection of the user-supplied fuxi recovery ramdisk."""
import argparse
import ctypes
import ctypes.util
import difflib
import hashlib
import json
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile

NEW_IMAGE_SHA = "56f5f36e9aaeb9e79815c702d9e9196c8c0e1b03d363ec4e4c9646cd4af1444c"
NEW_CPIO_SHA = "8e7b2178b92b04d1e8d50ff6e6b51fe48ec14cf8126cf7dd0e508ce378225c25"
OLD_IMAGE_SHA = "68f3829ba4b7faaf8b873fd0dce7dabd03b2bdd750debbae56b1dbe326f87da5"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unpack_legacy_lz4(blob):
    if blob[:4] != b"\x02\x21\x4c\x18":
        raise ValueError("ramdisk is not an LZ4 legacy stream")
    lib = ctypes.CDLL(ctypes.util.find_library("lz4"))
    decode = lib.LZ4_decompress_safe
    decode.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    decode.restype = ctypes.c_int
    pos = 4
    out = bytearray()
    while pos < len(blob):
        if len(blob) - pos < 4:
            raise ValueError("truncated LZ4 block size")
        size = struct.unpack_from("<I", blob, pos)[0]
        pos += 4
        if size == 0:
            if any(blob[pos:]):
                raise ValueError("nonzero data after LZ4 terminator")
            break
        if size > 8 * 1024 * 1024 + 64 * 1024 or size > len(blob) - pos:
            raise ValueError("invalid LZ4 block size")
        source = ctypes.create_string_buffer(blob[pos:pos + size])
        target = ctypes.create_string_buffer(8 * 1024 * 1024)
        n = decode(source, target, size, len(target))
        if n <= 0:
            raise ValueError(f"LZ4 decompression failed at {pos}: {n}")
        out.extend(target.raw[:n])
        if len(out) > 384 * 1024 * 1024:
            raise ValueError("ramdisk expansion exceeds bound")
        pos += size
    return bytes(out)


def entries(archive):
    pos = 0
    seen = set()
    while True:
        if archive[pos:pos + 6] not in (b"070701", b"070702") or pos + 110 > len(archive):
            raise ValueError(f"bad cpio header at {pos}")
        fields = [int(archive[pos + 6 + i * 8:pos + 14 + i * 8], 16) for i in range(13)]
        mode, size, name_size = fields[1], fields[6], fields[11]
        end_name = pos + 110 + name_size
        if not 1 <= name_size <= 4096 or end_name > len(archive) or archive[end_name - 1] != 0:
            raise ValueError("invalid cpio name")
        name = archive[pos + 110:end_name - 1].decode("utf-8", "strict")
        begin = (end_name + 3) & ~3
        end = begin + size
        if end > len(archive):
            raise ValueError("truncated cpio entry")
        if name == "TRAILER!!!":
            if any(archive[(end + 3) & ~3:]):
                raise ValueError("unexpected data after cpio trailer")
            return
        if name in seen:
            raise ValueError(f"duplicate cpio name: {name}")
        seen.add(name)
        yield name, mode, archive[begin:end]
        pos = (end + 3) & ~3


def elf_evidence(content):
    with tempfile.TemporaryDirectory(prefix="fuxi-a17-elf-") as d:
        path = Path(d) / "selected.elf"
        path.write_bytes(content)
        output = subprocess.check_output(["readelf", "-d", "-sW", str(path)], text=True)
    symbols = []
    for line in output.splitlines():
        if re.search(r"\b(Decrypt_DE|Decrypt_User|crypto_qti_[A-Za-z_]+|qcom_scm_[A-Za-z_]*ice_key|qcom_scm_derive_raw_secret|retrieveKey|installKey)\b", line):
            symbols.append(line.split()[-1])
    strings = [m.group().decode() for m in re.finditer(rb"[\x20-\x7e]{6,}", content)]
    return {
        "needed": re.findall(r"Shared library: \[(.*?)\]", output),
        "interface_symbols": sorted(set(symbols)),
        "module_abi": [s for s in strings if s.startswith(("vermagic=", "depends="))],
        "version_strings": sorted(set(s for s in strings if re.search(r"TWRP|Android 1[567]|A1[567]", s, re.I) and len(s) < 160))[:40],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--compare-old", type=Path)
    args = ap.parse_args()
    image = args.image.read_bytes()
    if digest(image) != NEW_IMAGE_SHA:
        raise ValueError("new image differs from the audited A17 input")
    if image[:8] != b"ANDROID!" or len(image) != 104857600:
        raise ValueError("unexpected image magic or length")
    kernel, rd_size, os_version, header_size = struct.unpack_from("<IIII", image, 8)
    version = struct.unpack_from("<I", image, 40)[0]
    if kernel != 0 or version != 4 or header_size not in (1580, 1584) or not 0 < rd_size <= len(image) - 4096:
        raise ValueError("unexpected boot v4 layout")
    compressed = image[4096:4096 + rd_size]
    archive = unpack_legacy_lz4(compressed)
    if digest(archive) != NEW_CPIO_SHA:
        raise ValueError("new ramdisk differs from the audited A17 input")
    wanted = {
        "prop.default", "init.recovery.qcom.rc", "system/etc/recovery.fstab", "system/etc/twrp.flags",
        "system/bin/recovery", "vendor/bin/hw/android.hardware.security.keymint-service-qti",
        "vendor/lib64/libqtikeymint.so", "vendor/lib64/libminkdescriptor.so",
        "vendor/lib/modules/1.1/ufs_qcom.ko", "vendor/lib/modules/1.1/ufshcd-crypto-qti.ko",
        "vendor/lib/modules/1.1/crypto-qti-common.ko", "vendor/lib/modules/1.1/crypto-qti-hwkm.ko",
        "vendor/lib/modules/1.1/qcom-scm.ko",
    }
    text_names = {"prop.default", "init.recovery.qcom.rc", "system/etc/recovery.fstab", "system/etc/twrp.flags"}
    selected = {}
    manifest = {}
    new_prop = None
    names = []
    for name, mode, content in entries(archive):
        names.append(name)
        manifest[name] = (mode, len(content), digest(content))
        if name == "prop.default":
            new_prop = content
        if name not in wanted:
            continue
        if not stat.S_ISREG(mode):
            raise ValueError(f"evidence file not regular: {name}")
        rec = {"bytes": len(content), "sha256": digest(content)}
        if content[:4] == b"\x7fELF":
            rec.update(elf_evidence(content))
        elif name in text_names:
            lines = content.decode("utf-8", "replace").splitlines()
            if name == "prop.default":
                rec["selected_lines"] = [x for x in lines if x.startswith(("ro.twrp.", "ro.build.version.", "ro.product.", "ro.vendor.build.version."))]
            else:
                rec["selected_lines"] = [x for x in lines if re.search(r"/data|/metadata|fileencryption|metadata_encryption|inlinecrypt|keymint|gatekeeper|qsee|keystore|vold", x, re.I)]
        selected[name] = rec
    report = {
        "schema": 1, "scope": "static image inspection only; no decryption or device execution",
        "image_name": args.image.name, "image_bytes": len(image), "image_sha256": digest(image),
        "boot_header": {"version": version, "header_size": header_size, "kernel_size": kernel,
                        "ramdisk_size": rd_size, "os_version_raw": f"0x{os_version:08x}"},
        "ramdisk_lz4_sha256": digest(compressed), "cpio_bytes": len(archive), "cpio_sha256": digest(archive),
        "entries": len(names), "module_entries": sum(x.endswith(".ko") for x in names),
        "missing_expected": sorted(wanted - selected.keys()), "files": selected,
    }
    if args.compare_old:
        old_image = args.compare_old.read_bytes()
        if digest(old_image) != OLD_IMAGE_SHA:
            raise ValueError("old image differs from the archived A16 input")
        if old_image[:8] != b"ANDROID!" or struct.unpack_from("<I", old_image, 40)[0] != 4:
            raise ValueError("old comparison is not boot v4")
        old_size = struct.unpack_from("<I", old_image, 12)[0]
        old_archive = unpack_legacy_lz4(old_image[4096:4096 + old_size])
        old_manifest = {}
        old_prop = None
        for name, mode, content in entries(old_archive):
            old_manifest[name] = (mode, len(content), digest(content))
            if name == "prop.default":
                old_prop = content
        report["comparison_old"] = {
            "image_name": args.compare_old.name, "image_sha256": digest(old_image),
            "cpio_sha256": digest(old_archive), "entries": len(old_manifest),
            "added": sorted(manifest.keys() - old_manifest.keys()),
            "removed": sorted(old_manifest.keys() - manifest.keys()),
            "changed": [dict(path=name, old_sha256=old_manifest[name][2], new_sha256=manifest[name][2])
                        for name in sorted(manifest.keys() & old_manifest.keys()) if manifest[name] != old_manifest[name]],
            "prop_default_diff": list(difflib.unified_diff(
                old_prop.decode("utf-8").splitlines(), new_prop.decode("utf-8").splitlines(),
                fromfile="old/prop.default", tofile="new/prop.default", lineterm="")),
        }
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "files"}, indent=2))


if __name__ == "__main__":
    main()
