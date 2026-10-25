#!/usr/bin/env python3
"""ASan/UBSan tests of the native UFS command core against a modeled controller."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--edk2", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    ufs = root / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe"
    data = root / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe"
    edk = args.edk2.resolve()
    machine = "AArch64" if platform.machine() in ("arm64", "aarch64") else "X64"

    # Independently generated SHA-256 vectors (FIPS 180-4 reference lengths).
    vectors = [b"", b"abc", b"a" * 63, b"a" * 64, b"a" * 65,
               bytes(range(256)) * 3, bytes(range(256)) * 7 + b"tail",
               struct.pack("<Q", 0x1D84000) * 9, b"fuxi-twrp-data-port\n"]
    with tempfile.TemporaryDirectory(prefix="fuxi-ufs-test-") as temporary:
        temp = Path(temporary)
        vectors_path = temp / "sha256.txt"
        vectors_path.write_text("".join(
            data.hex() + " " + hashlib.sha256(data).hexdigest() + "\n"
            for data in vectors))
        command = [shutil.which("clang") or "clang", "-std=c11", "-Wall", "-Wextra",
                   "-Werror", "-fshort-wchar", "-fsanitize=address,undefined",
                   "-fno-omit-frame-pointer",
                   "-I", str(edk / "MdePkg/Include"), "-I", str(edk / "MdePkg/Include" / machine),
                   "-I", str(ufs), str(root / "tools/tests/fuxi_ufs_host.c"),
                   str(ufs / "UfsCore.c"), str(ufs / "UfsSha256.c")]
        binary = temp / "host-tests"
        subprocess.run([*command, "-o", str(binary)], check=True)
        subprocess.run([str(binary), str(vectors_path)], check=True)

    report = dict(result="passed", sha256_vectors=len(vectors),
                  sanitizers=["address", "undefined"],
                  scope=("modeled-controller command core (UTRD/UPIU, poll policy, "
                         "quarantine, responses, sense), queue stop plan, SMMU "
                         "planner/configuration; no device, MMIO or SMC execution"),
                  sources={str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in [ufs / "UfsCore.c", ufs / "UfsCore.h", ufs / "UfsSha256.c",
                                     ufs / "UfsSha256.h", root / "tools/tests/fuxi_ufs_host.c",
                                     Path(__file__)]})
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
