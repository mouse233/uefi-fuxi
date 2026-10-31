#!/usr/bin/env python3
"""Production root-context batch with synthetic monitor; no phone or MAC proof."""
import argparse, hashlib, json, platform, shutil, subprocess, tempfile
from pathlib import Path

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--edk2',type=Path,required=True);p.add_argument('--report',type=Path,required=True)
a=p.parse_args()
if platform.system()!='Linux':p.error('run in build container')
root=Path(__file__).resolve().parents[1];native=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe';data=native.parent/'FuxiDataProbeDxe'
test=root/'tools/tests/m3_smci_resume_host.c'
with tempfile.TemporaryDirectory(prefix='rootctx-entry-') as tmp:
 exe=str(Path(tmp)/'test')
 subprocess.run([shutil.which('clang'),'-std=c11','-Wall','-Wextra','-Werror','-Wno-macro-redefined','-fshort-wchar','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-DFUXI_M3_ROOT_TRUST_QUERY=1','-I'+str(a.edk2/'MdePkg/Include'),'-I'+str(a.edk2/'MdePkg/Include/AArch64'),'-I'+str(native),'-I'+str(data),str(test),str(native/'UfsReport.c'),str(data/'DataReadOnly.c'),'-o',exe],check=True)
 output=subprocess.check_output([exe],text=True)
files=[Path(__file__),test,native/'M3SmciDiagnostic.inc',native/'M3BridgeDiagnostic.inc',native/'M3RootTrustDiagnostic.inc',native/'M3RootTrustPublic.h',native/'UfsReport.c',native/'UfsReport.h',data/'DataReadOnly.c',data/'DataReadOnly.h']+[root/'tools/tests'/n for n in ('m3_root_trust_monitor.inc','m3_root_trust_cases.inc','m3_root_trust_fixture.inc')]
report=dict(result='passed',cases=32,output=output.strip(),sanitizers=['address','undefined'],scope='Production batch, synthetic transport only; MAC unverified. No real TA recovery or key files.',sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files})
a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2)+'\n');print(output.strip())
