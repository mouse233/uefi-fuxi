#!/usr/bin/env python3
"""Host sanitization tests and reproducible static AArch64 DM status build."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--binary', type=Path, required=True)
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = root / 'tools/m3_dm_status.c'
    compiler = shutil.which('clang')
    cross = shutil.which('aarch64-linux-gnu-gcc')
    if not compiler or not cross:
        raise SystemExit('clang and aarch64-linux-gnu-gcc are required')
    with tempfile.TemporaryDirectory(prefix='m3-dm-test-') as temp:
        binary = Path(temp) / 'host-test'
        subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        str(source), '-o', str(binary)], check=True)
        subprocess.run([str(binary), '--selftest'], check=True)
    args.binary.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([cross, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', '-static',
                    str(source), '-o', str(args.binary)], check=True)
    description = subprocess.check_output(['file', str(args.binary)], text=True)
    if 'ARM aarch64' not in description or 'statically linked' not in description:
        raise RuntimeError('unexpected AArch64 helper format')
    report = {'result': 'passed', 'sanitizers': ['address', 'undefined'],
              'scope': 'offline parser and redaction tests; static AArch64 status query binary',
              'binary_sha256': sha(args.binary),
              'sources': {str(path.relative_to(root)): sha(path) for path in (source, Path(__file__))}}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
