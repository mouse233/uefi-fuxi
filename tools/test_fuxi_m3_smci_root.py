#!/usr/bin/env python3
"""Run C2 production lifecycle failure vectors with simulated SMC under sanitizers."""
import argparse,hashlib,json,platform,shutil,subprocess,tempfile
from pathlib import Path


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--edk2',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
 root=Path(__file__).resolve().parents[1]
 src=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe'
 native=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe'
 paths=[src/'DataReadOnly.c',src/'DataReadOnly.h',native/'M3BridgeDiagnostic.inc',
        native/'M3SmciDiagnostic.inc',root/'tools/tests/m3_smci_root_host.c',Path(__file__)]
 arch='AArch64' if platform.machine() in ('aarch64','arm64') else 'X64'
 with tempfile.TemporaryDirectory(prefix='fuxi-c2-') as temp:
  binary=Path(temp)/'root-host'
  cmd=[shutil.which('clang') or 'clang','-std=c11','-Wall','-Wextra','-Werror','-fshort-wchar',
       '-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(a.edk2/'MdePkg/Include'),
       '-I',str(a.edk2/'MdePkg/Include'/arch),'-I',str(src),'-I',str(native),
       str(root/'tools/tests/m3_smci_root_host.c'),str(src/'DataReadOnly.c'),'-o',str(binary)]
  for mode in (0,1):
   for profile in (0,1):
    subprocess.run([*cmd, "-DFUXI_M3_SMCI_OBJECT="+str(mode), "-DFUXI_M3_BRIDGE_HLOS="+str(profile)],check=True)
    subprocess.run([str(binary)],check=True)
 report=dict(result='passed',vectors=148,vectors_per_configuration=37,modes=["legacy","object"],bridge_profiles=["zero-vm-control","hlos"],sanitizers=['address','undefined'],
  scope='Production C2 root register/release and bridge lifetime, all register/response/object/buffer errors retain resources; simulated SMC only',
  sources={str(x.relative_to(root)):hashlib.sha256(x.read_bytes()).hexdigest() for x in paths})
 a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
