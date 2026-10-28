#!/usr/bin/env python3
"""Exercise production bridge resource ownership with simulated SMC only."""
import argparse,hashlib,json,platform,shutil,subprocess,tempfile
from pathlib import Path
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--edk2',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
 root=Path(__file__).resolve().parents[1];src=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe';native=src.parent/'FuxiNativeUfsDxe'
 paths=[src/'DataReadOnly.c',src/'DataReadOnly.h',native/'M3BridgeDiagnostic.inc',root/'tools/tests/m3_bridge_lifetime_host.c',Path(__file__)]
 arch='AArch64' if platform.machine() in ('aarch64','arm64') else 'X64'
 with tempfile.TemporaryDirectory(prefix='fuxi-bridge-lifetime-') as tmp:
  binary=Path(tmp)/'host'
  cmd=[shutil.which('clang') or 'clang','-std=c11','-Wall','-Wextra','-Werror','-fshort-wchar','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(a.edk2/'MdePkg/Include'),'-I',str(a.edk2/'MdePkg/Include'/arch),'-I',str(src),'-I',str(native),str(paths[3]),str(paths[0]),'-o',str(binary)]
  for profile,large in ((0,0),(1,0),(1,1)):
   subprocess.run(cmd+['-DFUXI_M3_BRIDGE_HLOS='+str(profile),'-DFUXI_M3_BRIDGE_LARGE='+str(large)],check=True)
   subprocess.run([str(binary)],check=True)
 report=dict(result='passed',vectors=36,vectors_per_profile=12,profiles=['zero-vm-control','hlos','hlos-0x82000'],sanitizers=['address','undefined'],scope='production standard bridge lifecycle: a0/a1 gates, a2 64-bit handle, old tuple refusal, no post-create unknown wipe/free/retry; no hardware',sources={str(x.relative_to(root)):hashlib.sha256(x.read_bytes()).hexdigest() for x in paths})
 a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
