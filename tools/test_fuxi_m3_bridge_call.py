#!/usr/bin/env python3
"""Compile and run the scalar SMC64 builder vectors on the host."""
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
    parser.add_argument('--edk2', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    src = root / 'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe'
    edk = args.edk2.resolve()
    arch = 'AArch64' if platform.machine() in ('aarch64', 'arm64') else 'X64'
    paths = [src / 'DataReadOnly.c', src / 'DataReadOnly.h',
             root / 'tools/tests/m3_bridge_host.c', Path(__file__)]
    command = [shutil.which('clang') or 'clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
               '-fshort-wchar', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
               '-I', str(edk / 'MdePkg/Include'), '-I', str(edk / 'MdePkg/Include' / arch),
               '-I', str(src), str(paths[2]), str(paths[0])]
    with tempfile.TemporaryDirectory(prefix='fuxi-m3-bridge-') as temp:
        binary = Path(temp) / 'm3-bridge-host'
        subprocess.run([*command, '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    report = {
        'result': 'passed', 'sanitizers': ['address', 'undefined'],
        'scope': ('scalar SMC64 register builders (FNID/arginfo/argument packing for '
                  'bridge enable/create/delete); no device, SMC, TA or key'),
        'sources': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in paths},
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
