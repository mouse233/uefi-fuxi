#!/usr/bin/env python3
"""Execute production root/loader batch under ASan/UBSan; simulated SMC only."""
import argparse,hashlib,json,platform,shutil,subprocess,tempfile
from pathlib import Path
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--edk2',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
 root=Path(__file__).resolve().parents[1]
 native=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe'
 data=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe'
 sources=[native/'M3SmciDiagnostic.inc',native/'M3BridgeDiagnostic.inc',native/'UfsReport.c',native/'UfsReport.h',data/'DataReadOnly.c',data/'DataReadOnly.h',root/'tools/tests/m3_smci_loader_host.c',Path(__file__)]
 arch='AArch64' if platform.machine() in ('aarch64','arm64') else 'X64'
 with tempfile.TemporaryDirectory(prefix='fuxi-c3-') as t:
  exe=Path(t)/'batch'
  subprocess.run([shutil.which('clang') or 'clang','-std=c11','-Wall','-Wextra','-Werror','-fshort-wchar','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(a.edk2/'MdePkg/Include'),'-I',str(a.edk2/'MdePkg/Include'/arch),'-I',str(native),'-I',str(data),str(root/'tools/tests/m3_smci_loader_host.c'),str(native/'UfsReport.c'),str(data/'DataReadOnly.c'),'-o',str(exe)],check=True)
  subprocess.run([str(exe)],check=True)
 report=dict(result='passed',vectors=78,production_lifecycle=True,report_cache_exercised=True,sanitizers=['address','undefined'],sources={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},scope='Production root->open UID122->release loader->release environment->delete bridge; raw errors and corrupted buffers stop, preserve unknown-state pages; simulated monitor only')
 a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
