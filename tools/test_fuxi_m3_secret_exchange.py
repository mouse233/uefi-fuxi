#!/usr/bin/env python3
"""Actual log-free exchange/KeyMint/core with a synthetic monitor and sanitizers."""
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
    root=Path(__file__).resolve().parents[1];src=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe'
    if platform.system()!='Linux':raise SystemExit('run this low-address gate test inside unixnu-fuxi-build-arm64 (Linux)')
    test=root/'tools/tests/m3_secret_exchange_host.c'
    files=[src/n for n in ('M3SecretExchange.c','M3KeyMintBackend.c','M3KeyRecovery.c','M3Secdiscardable.c')]
    a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text('{"result":"running"}\n')
    outputs=[]
    with tempfile.TemporaryDirectory(prefix='m3-secret-') as tmp:
        for enabled,probe in ((0,0),(1,0),(1,1)):
            exe=Path(tmp)/('test-'+str(enabled)+'-'+str(probe))
            command=[shutil.which('clang') or 'clang','-std=c11','-Wall','-Wextra','-Werror','-Wno-macro-redefined','-fshort-wchar','-g','-O1',
                     '-fsanitize=address,undefined','-fno-omit-frame-pointer',f'-DFUXI_M3_SECRET_EXCHANGE={enabled}',
                     f'-DFUXI_M3_CHARACTERISTICS_PROBE={probe}',
                     '-I'+str(a.edk2/'MdePkg/Include'),'-I'+str(a.edk2/'MdePkg/Include/AArch64'),'-I'+str(src),
                     str(test),*(str(f) for f in files),'-o',str(exe)]
            subprocess.run(command,check=True)
            result=subprocess.check_output([str(exe)],text=True);outputs.append(result.strip());print(result.strip())
    bound=[*files,test,Path(__file__),src/'M3SecretExchange.h',src/'M3KeyMintBackend.h',src/'M3KeyRecovery.h']
    report=dict(result='passed',outputs=outputs,sanitizers=['address','undefined'],
                scope='Default-off and real exchange adapter/core on a simulated monitor only; no device, live SMC, key recovery or GCM authentication.',
                sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in bound})
    a.report.write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
