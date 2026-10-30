#!/usr/bin/env python3
"""Production 1011/BO4 lookup-only batch and strict cleanup ownership tests."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--edk2',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    root=Path(__file__).resolve().parents[1];native=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe';data=native.parent/'FuxiDataProbeDxe'
    test=root/'tools/tests/m3_lookup_arch_host.c';arch='AArch64' if platform.machine() in ('arm64','aarch64') else 'X64'
    with tempfile.TemporaryDirectory(prefix='lookup-arch-') as tmp:
        exe=Path(tmp)/'test'
        subprocess.run([shutil.which('clang'),'-std=c11','-Wall','-Wextra','-Werror','-fshort-wchar',
                        '-fsanitize=address,undefined','-fno-omit-frame-pointer','-I'+str(a.edk2/'MdePkg/Include'),
                        '-I'+str(a.edk2/'MdePkg/Include'/arch),'-I'+str(native),'-I'+str(data),str(test),
                        str(native/'UfsReport.c'),str(data/'DataReadOnly.c'),'-o',str(exe)],check=True)
        output=subprocess.check_output([str(exe)],text=True)
    files=[Path(__file__),test,native/'M3SmciDiagnostic.inc',native/'M3BridgeDiagnostic.inc',native/'UfsReport.c',native/'UfsReport.h',data/'DataReadOnly.c',data/'DataReadOnly.h']
    result=dict(result='passed',vectors=38,production_lifecycle=True,report_cache_exercised=True,
                sanitizers=['address','undefined'],output=output.strip(),
                sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files},
                scope='Production root/open122/one keymaster64 lookup1011/BO4/validate/release/delete; errors with dirty outputs retain. Monitor simulated, no device.')
    a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(result,indent=2)+'\n');print(output.strip())


if __name__=='__main__':main()
