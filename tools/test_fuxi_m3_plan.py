#!/usr/bin/env python3
"""Compile and test production M3 metadata mapping arithmetic on the host."""
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
    paths = [src / 'M3DefaultKeyPlan.c', src / 'M3DefaultKeyPlan.h', src / 'DataReadOnly.h',
             root / 'tools/tests/m3_plan_host.c', Path(__file__)]
    command = [shutil.which('clang') or 'clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
               '-fshort-wchar', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
               '-I', str(edk / 'MdePkg/Include'), '-I', str(edk / 'MdePkg/Include' / arch),
               '-I', str(src), str(paths[3]), str(paths[0])]
    with tempfile.TemporaryDirectory(prefix='fuxi-m3-plan-') as temp:
        binary = Path(temp) / 'm3-plan-test'
        subprocess.run([*command, '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    report = {
        'result': 'passed', 'sanitizers': ['address', 'undefined'],
        'scope': 'metadata-only DUN/address planning; synthetic mapping, no device, key, SMC, ICE or IO',
        'sources': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
