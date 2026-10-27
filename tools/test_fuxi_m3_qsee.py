#!/usr/bin/env python3
"""Check QSEE audit rejects altered input without producing a report."""
import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from audit_fuxi_m3_qsee import EXPECTED


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ramdisk', required=True, type=Path)
    a = p.parse_args()
    audit = Path(__file__).with_name('audit_fuxi_m3_qsee.py')
    with tempfile.TemporaryDirectory(prefix='m3-qsee-audit-') as td:
        root = Path(td) / 'ramdisk'
        for name in EXPECTED:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(a.ramdisk / name, target)
        target = root / 'vendor/lib/modules/1.1/smcinvoke_dlkm.ko'
        with target.open('ab') as stream:
            stream.write(b'\x00')
        report = Path(td) / 'report.json'
        for flags in ([], ['-O']):
            result = subprocess.run([sys.executable, *flags, str(audit), '--ramdisk', str(root), '--output', str(report)], capture_output=True)
            if result.returncode == 0 or report.exists():
                raise SystemExit('modified input was accepted or produced a report')
    print('PASS: changed smcinvoke module rejected before reporting')


if __name__ == '__main__':
    main()
