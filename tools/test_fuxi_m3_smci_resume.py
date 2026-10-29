#!/usr/bin/env python3
"""Run production SCM continuation with a simulated monitor under ASan and UBSan."""
import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--edk2', type=Path, required=True)
p.add_argument('--report', type=Path, required=True)
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
native = root / 'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe'
data = root / 'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe'
test = root / 'tools/tests/m3_smci_resume_host.c'
sources = [native/'M3SmciDiagnostic.inc', native/'M3BridgeDiagnostic.inc', native/'UfsReport.c',
           native/'UfsReport.h', data/'DataReadOnly.c', data/'DataReadOnly.h', test, Path(__file__)]
arch = 'AArch64' if platform.machine() in ('aarch64', 'arm64') else 'X64'
with tempfile.TemporaryDirectory(prefix='fuxi-version-') as tmp:
    exe = Path(tmp)/'test'
    subprocess.run([shutil.which('clang') or 'clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
        '-fshort-wchar', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
        '-I', str(a.edk2/'MdePkg/Include'), '-I', str(a.edk2/'MdePkg/Include'/arch),
        '-I', str(native), '-I', str(data), str(test), str(native/'UfsReport.c'),
        str(data/'DataReadOnly.c'), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
report = dict(result='passed', vectors=46, sanitizers=['address','undefined'],
    scope='Production SCM continuation, simulated monitor only; interruptions preserve x6 and failures retain bridge',
    sources={str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest() for f in sources})
a.report.parent.mkdir(parents=True, exist_ok=True)
a.report.write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, indent=2))
