#!/usr/bin/env python3
"""Instrument existing production integration tests without editing their files.

The added monitor observer checks handle continuity and absence of calls after
quarantine. Filesystem/monitor are still synthetic, never real TA init/recovery.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

OBSERVER=r'''
static UINT32 LifeApp;
static int LifeLoads,LifeVersion,LifeConfigure,LifeBegin,LifeRelease,LifeDelete;
VOID EFIAPI ArmCallSmc(ARM_SMC_ARGS *a){
 UINT64 fn=a->Arg0;UINT32 obj=0,op=0,count=0,cmd=0;
 if(fn==0x42000c1c){LifeApp=0;LifeLoads=LifeVersion=LifeConfigure=LifeBegin=LifeRelease=LifeDelete=0;}
 if((fn==0x72000602||fn==1)&&Page){
  obj=*(UINT32*)Page;op=*(UINT32*)(Page+4);count=*(UINT32*)(Page+8);
  if(op==0&&count==0x424){
   cmd=*(UINT32*)(Page+96);assert(LifeLoads==1&&LifeApp>1&&obj==LifeApp&&!LifeRelease);
   if(cmd==0x200)++LifeVersion;
   else if(cmd==0x2116){assert(LifeVersion);++LifeConfigure;}
   else {assert(LifeConfigure);if(cmd==0x310f)++LifeBegin;}
  }
  if(op==0xffff&&obj==LifeApp){assert(!LifeRelease);++LifeRelease;}
 }
 if(fn==0x42000c1d){assert(LifeRelease==1);++LifeDelete;}
 ExistingArmCallSmc(a);
 if(fn==0x72000602&&op==1&&count==0x1012){
  assert(!LifeLoads);++LifeLoads;LifeApp=*(UINT32*)(Page+36);assert(LifeApp==App());
 }
}
'''
CHECK=r'''
static void CheckLifecycle(void){
 if(!Calls){printf("TRACE case=%d no-dispatch=1\n",Scenario);return;}
 assert(LifeLoads==1&&LifeVersion==1);
 if(mRecoveryRetained||!Frees)assert(!LifeRelease&&!LifeDelete);
 if(Frees)assert(LifeRelease==1&&LifeDelete==1);
 printf("TRACE case=%d load=%d version=%d configure=%d begin=%d release=%d delete=%d retained=%d\n",
  Scenario,LifeLoads,LifeVersion,LifeConfigure,LifeBegin,LifeRelease,LifeDelete,mRecoveryRetained);
}
'''


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--edk2',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    if platform.system()!='Linux':raise SystemExit('run in unixnu-fuxi-build-arm64')
    root=Path(__file__).resolve().parents[1];native=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiNativeUfsDxe'
    data=native.parent/'FuxiDataProbeDxe';tests=root/'tools/tests'
    template=(tests/'m3_smci_resume_host.c').read_text()
    definition='VOID EFIAPI ArmCallSmc(ARM_SMC_ARGS *a){'
    assert template.count(definition)==1
    template=template.replace(definition,'VOID EFIAPI ExistingArmCallSmc(ARM_SMC_ARGS *a){',1)
    anchor='#include "M3BridgeDiagnostic.inc"';assert template.count(anchor)==1
    template=template.replace(anchor,OBSERVER+'\n'+anchor,1)
    anchor='static void SetupTa(void){';assert template.count(anchor)==1
    template=template.replace(anchor,CHECK+'\n'+anchor,1)
    # The configured case loop lives in an include; create an instrumented copy
    # in the temporary directory, preserving every existing assertion.
    cases=(tests/'m3_configured_recovery_cases.inc').read_text()
    assert cases.count('FnuSmciRootProbe();')==1
    cases=cases.replace('FnuSmciRootProbe();','FnuSmciRootProbe();CheckLifecycle();')
    sources=[data/n for n in ('DataReadOnly.c','M3KeyRecovery.c','M3Secdiscardable.c','M3KeyMintBackend.c','M3SecretExchange.c')]+[native/'UfsReport.c']
    profiles=[]
    with tempfile.TemporaryDirectory(prefix='m3-lifecycle-') as tmp:
        temp=Path(tmp);(temp/'test.c').write_text(template);(temp/'m3_configured_recovery_cases.inc').write_text(cases)
        for patch in (20261005,20991231):
            exe=temp/('test-'+str(patch))
            cmd=[shutil.which('clang'),'-std=c11','-Wall','-Wextra','-Werror','-Wno-macro-redefined','-fshort-wchar','-g','-O1',
                 '-fsanitize=address,undefined','-fno-omit-frame-pointer','-DTEST_RECOVERY_ENTRY=1','-DTEST_CONFIGURE_RECOVERY=1',
                 '-DFUXI_M3_CONFIGURE_PATCH='+str(patch),'-DFUXI_M3_CHARACTERISTICS_PROBE=0','-DFUXI_M3_SECRET_EXCHANGE=1',
                 '-I'+str(temp),'-I'+str(tests),'-I'+str(a.edk2/'MdePkg/Include'),'-I'+str(a.edk2/'MdePkg/Include/AArch64'),
                 '-I'+str(native),'-I'+str(data),str(temp/'test.c'),*(str(f) for f in sources),'-o',str(exe)]
            subprocess.run(cmd,check=True);output=subprocess.check_output([str(exe)],text=True)
            traces=[line for line in output.splitlines() if line.startswith('TRACE ')]
            assert len(traces)==26 and 'PASS 27 configured recovery/session cases' in output
            assert any('case=15 ' in row and 'release=0 delete=0 retained=1' in row for row in traces)
            profiles.append(dict(configure_patch=patch,cases=27,traced_batches=26,output=output.strip()))
    files=[Path(__file__),*sources,tests/'m3_smci_resume_host.c',tests/'m3_recovery_entry_fixture.inc',tests/'m3_configure_monitor.inc',
           tests/'m3_configured_recovery_cases.inc',native/'M3BridgeDiagnostic.inc',native/'M3SmciDiagnostic.inc',
           native/'M3RecoveryDiagnostic.inc',native/'M3ConfigureDiagnostic.inc',data/'M3SecretExchange.h',data/'M3KeyMintBackend.h',
           data/'M3KeyRecovery.h',data/'M3KeyRecoveryF2fs.h']
    report=dict(result='passed',profiles=profiles,sanitizers=['address','undefined'],
                generated_harness_sha256=hashlib.sha256(template.encode()).hexdigest(),
                generated_case_loop_sha256=hashlib.sha256(cases.encode()).hexdigest(),
                scope='Actual production batch/backend/exchange + observer. Synthetic filesystem/monitor only; not a secure-world lifecycle trace.',
                sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files})
    a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS 54 production integration cases, 52 batch traces; same App and retained-state guards; simulated monitor only')


if __name__=='__main__':main()
