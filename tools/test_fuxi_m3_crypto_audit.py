#!/usr/bin/env python3
"""Ensure fixed-image crypto audit rejects a changed module."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile
import audit_fuxi_m3_crypto as audit

p=argparse.ArgumentParser();p.add_argument('--modules',type=Path,required=True);a=p.parse_args()
script=Path(audit.__file__)
with tempfile.TemporaryDirectory(prefix='fuxi-crypto-audit-test-') as tmp:
    d=Path(tmp)
    for name in audit.EXPECTED: shutil.copyfile(a.modules/name,d/name)
    report=d/'result.json'
    subprocess.run(['python3',str(script),'--modules',str(d),'--output',str(report)],check=True,stdout=subprocess.DEVNULL)
    bad=d/'qcom-scm.ko';data=bytearray(bad.read_bytes());data[-1]^=1;bad.write_bytes(data)
    failed=subprocess.run(['python3',str(script),'--modules',str(d),'--output',str(report)],capture_output=True,text=True)
    if failed.returncode == 0 or 'qcom-scm.ko' not in failed.stderr:
        raise SystemExit('modified module was not rejected')
print('positive audit and tamper rejection: passed')
