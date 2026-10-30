#!/usr/bin/env python3
"""ASan/UBSan probe for the read-only getKeyCharacteristics (0x2109) helper."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--edk2',type=Path,required=True)
    p.add_argument('--report',type=Path,required=True)
    a=p.parse_args(); root=Path(__file__).resolve().parents[1]
    a.report.parent.mkdir(parents=True,exist_ok=True)
    a.report.write_text('{"result":"running"}\n')
    src=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe'
    test=root/'tools/tests/m3_characteristics_host.c'
    with tempfile.TemporaryDirectory(prefix='m3-chars-') as tmp:
        binary=Path(tmp)/'test'
        command=['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror','-Wno-macro-redefined','-fshort-wchar','-g','-O1',
                 '-fsanitize=address,undefined','-fno-omit-frame-pointer',
                 '-I'+str(a.edk2/'MdePkg/Include'),'-I'+str(a.edk2/'MdePkg/Include/AArch64'),
                 '-I'+str(src),str(test),str(src/'M3KeyMintBackend.c'),'-o',str(binary)]
        subprocess.run(command,check=True)
        result=subprocess.check_output([str(binary)],text=True)
        print(result.strip())
    bound=[src/'M3KeyMintBackend.c',src/'M3KeyMintBackend.h',test,Path(__file__)]
    report=dict(result='passed',host_output=result.strip(),sanitizers=['address','undefined'],
                sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in bound},
                scope='Synthetic transport only. Tests retain failed shared pages/requests, reject reentry/begin, '
                      'and withhold partial version fields. Request is map{23:blob,29:bstr(params)}; '
                      'no live SMC, TA, real key blob or vendor response.')
    a.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(result='passed')))


if __name__=='__main__':main()
