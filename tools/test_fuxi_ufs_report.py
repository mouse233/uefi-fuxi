#!/usr/bin/env python3
"""ASan/UBSan qualification of the production immutable UFS text cache."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--edk2", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    ufs = root / "Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe"
    edk = args.edk2.resolve()
    arch = "AArch64" if platform.machine() in ("arm64", "aarch64") else "X64"
    with tempfile.TemporaryDirectory(prefix="fuxi-ufs-report-") as directory:
        binary = Path(directory) / "report-test"
        command = [shutil.which("clang") or "clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                   "-fshort-wchar", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                   "-I", str(edk / "MdePkg/Include"), "-I", str(edk / "MdePkg/Include" / arch),
                   "-I", str(ufs), str(root / "tools/tests/fuxi_ufs_report_host.c"),
                   str(ufs / "UfsReport.c"), "-o", str(binary)]
        subprocess.run(command, check=True)
        subprocess.run([str(binary)], check=True)
    sources = [ufs / "UfsReport.c", ufs / "UfsReport.h", root / "tools/tests/fuxi_ufs_report_host.c",
               root / "Platforms/Xiaomi/fuxiPkg/Include/Protocol/FuxiUfsReport.h", Path(__file__)]
    report = dict(result="passed", sanitizers=["address", "undefined"],
                  scope="bounded immutable text cache, truncation/overflow accounting, CRLF trimming, repeated replay; no hardware IO",
                  sources={str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources})
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
