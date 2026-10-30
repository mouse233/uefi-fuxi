#!/usr/bin/env python3
"""Production read/recover/wipe/session lifecycle with a fake monitor, in Linux."""
import argparse,hashlib,json,platform,shutil,subprocess,tempfile
from pathlib import Path

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--edk2',type=Path,required=True);p.add_argument('--report',type=Path,required=True);p.add_argument('--configured',action='store_true');a=p.parse_args()
 if platform.system()!='Linux':raise SystemExit('run in unixnu-fuxi-build-arm64')
 root=Path(__file__).resolve().parents[1];native=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe';data=native.parent/'FuxiDataProbeDxe'
 test=root/'tools/tests/m3_smci_resume_host.c'
 sources=[data/n for n in ('DataReadOnly.c','M3KeyRecovery.c','M3Secdiscardable.c','M3KeyMintBackend.c','M3SecretExchange.c')]+[native/'UfsReport.c']
 a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text('{"result":"running"}\n')
 with tempfile.TemporaryDirectory(prefix='recovery-entry-') as tmp:
  exe=Path(tmp)/'test'
  cmd=[shutil.which('clang'),'-std=c11','-Wall','-Wextra','-Werror','-Wno-macro-redefined','-fshort-wchar','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-DTEST_RECOVERY_ENTRY=1','-DFUXI_M3_SECRET_EXCHANGE=1','-I'+str(a.edk2/'MdePkg/Include'),'-I'+str(a.edk2/'MdePkg/Include/AArch64'),'-I'+str(native),'-I'+str(data),str(test),*(str(x) for x in sources),'-o',str(exe)]
  cmd.insert(1,'-DTEST_CONFIGURE_RECOVERY='+str(int(a.configured)))
  subprocess.run(cmd,check=True);text=subprocess.check_output([str(exe)],text=True);print(text.strip())
 files=[*sources,test,root/'tools/tests/m3_recovery_entry_fixture.inc',root/'tools/tests/m3_recovery_entry_cases.inc',native/'M3RecoveryDiagnostic.inc',native/'M3SmciDiagnostic.inc',native/'M3BridgeDiagnostic.inc',data/'M3KeyRecoveryF2fs.h',data/'M3KeyRecovery.h',data/'M3KeyMintBackend.h',data/'M3SecretExchange.h',Path(__file__)]
 files += [native/'M3ConfigureDiagnostic.inc',root/'tools/tests/m3_configure_monitor.inc',root/'tools/tests/m3_configured_recovery_cases.inc']
 report=dict(result='passed',cases=27 if a.configured else 17,configured=a.configured,sanitizers=['address','undefined'],output=text.strip(),scope='Actual production recovery/session integration, synthetic filesystem/monitor only. No phone or GCM/KeyMint proof.',sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files})
 a.report.write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
