#!/usr/bin/env python3
"""Compile the actual TA reader with simulated partition IO, never a device."""
import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('--edk2',type=Path,required=True);p.add_argument('--partition',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
root=Path(__file__).resolve().parents[1]
native=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe'
data=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe'
source=native/'FuxiNativeUfsDxe.c'; test=root/'tools/tests/m3_ta_read_host.c'
assert hashlib.sha256(a.partition.read_bytes()).hexdigest()=='2fc838a8f0ed572ec77b7db2fe39ab4e81d0aa038bfad482b88087a27bf43cc6'
text=source.read_text(); start=text.index('STATIC EFI_STATUS FnuLoadTaImage('); end=text.index('\n#endif\nSTATIC BOOLEAN mLun4Passed',start)
arch='AArch64' if platform.machine() in ('aarch64','arm64') else 'X64'
with tempfile.TemporaryDirectory(prefix='fuxi-ta-read-') as t:
 path=Path(t);(path/'ta_load_under_test.inc').write_text(text[start:end]+'\n');exe=path/'test'
 subprocess.run([shutil.which('clang') or 'clang','-std=c11','-Wall','-Wextra','-Werror','-fshort-wchar','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(a.edk2/'MdePkg/Include'),'-I',str(a.edk2/'MdePkg/Include'/arch),'-I',str(native),'-I',str(data),'-I',str(path),str(test),str(native/'UfsSha256.c'),'-o',str(exe)],check=True)
 subprocess.run([str(exe),str(a.partition)],check=True)
sources=[source,native/'UfsSha256.c',native/'UfsSha256.h',data/'DataReadOnly.h',test,Path(__file__)]
report={'result':'passed','vectors':11,'sanitizers':['address','undefined'],'scope':'Actual FnuLoadTaImage function with simulated partition and pinned TA copy; no device', 'sources':{str(x.relative_to(root)):hashlib.sha256(x.read_bytes()).hexdigest() for x in sources}}
a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
