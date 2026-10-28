from pathlib import Path
import argparse,subprocess,tempfile
parser=argparse.ArgumentParser();parser.add_argument('--edk2',type=Path,required=True);args=parser.parse_args();root=Path(__file__).resolve().parents[1]; data=root/'Platforms/Xiaomi/fuxiPkg/Drivers/FuxiDataProbeDxe'; native=data.parent/'FuxiNativeUfsDxe'
s=(native/'FuxiNativeUfsDxe.c').read_text();start=s.index('STATIC BOOLEAN mLun4Passed');end=s.index('\n#endif',start);source=s[start:end]
h=r'''
#include "DataReadOnly.h"
#include <assert.h>
#include <stdio.h>
typedef struct {UINT8 Lun; UINT64 Last;} FNU_DIAG_LUN;
static int mDev,mOps;static BOOLEAN mPoisoned;static int mode,hashcalls;
#define FNU_TIMEOUT_NOP 1
#define FNU_TIMEOUT_READ 1
#define FNU_POLLS(X) (X)
static void FnuLog(const CHAR16 *f,...){(void)f;}
static EFI_STATUS FnuLun4Read(VOID *c,UINT64 l,UINTN n,VOID *b){(void)c;(void)l;(void)n;(void)b;return EFI_SUCCESS;}
static EFI_STATUS FnuTestUnitReadyLun(void*a,void*b,UINT8 l,UINTN n){(void)a;(void)b;(void)n;assert(l==4);return mode==1?EFI_DEVICE_ERROR:EFI_SUCCESS;}
static EFI_STATUS FnuReadCapacityLun(void*a,void*b,UINT8 l,UINT32*last,UINT32*block,UINTN n){(void)a;(void)b;(void)l;(void)n;*last=1000;*block=mode==2?512:4096;return mode==3?EFI_DEVICE_ERROR:EFI_SUCCESS;}
EFI_STATUS FdpReadGpt(const FDP_DISK*d,VOID*s,UINTN n,FDP_PARTITIONS*p){(void)d;(void)s;(void)n;p->KeymasterA.Present=mode!=5;p->KeymasterB.Present=TRUE;p->KeymasterA.First=1;p->KeymasterA.Last=128;p->KeymasterB.First=129;p->KeymasterB.Last=256;return mode==4?EFI_DEVICE_ERROR:EFI_SUCCESS;}
static EFI_STATUS FnuHashKeymaster(const FDP_DISK*d,const FDP_PARTITION*p,const CHAR16*n,const UINT8 h[32],VOID*s){(void)d;(void)p;(void)n;(void)h;(void)s;hashcalls++;return mode==5+hashcalls?EFI_COMPROMISED_DATA:EFI_SUCCESS;}
'''+source+r'''
int main(void){UINT8 scratch[1];for(mode=0;mode<8;mode++){hashcalls=0;mPoisoned=FALSE;mLun4Passed=RunLun4Keys(scratch);if(mode==0){assert(mLun4Passed&&hashcalls==2);}else{assert(!mLun4Passed);if(mode<=5)assert(hashcalls==0);if(mode==6)assert(hashcalls==1);if(mode==7)assert(hashcalls==2);}}puts("LUN4 production gate: success and 7 failure paths passed");}
'''
edk=args.edk2.resolve()/'MdePkg/Include'
with tempfile.TemporaryDirectory() as t:
 p=Path(t)/'x.c';p.write_text(h);exe=Path(t)/'x';subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-fshort-wchar','-fsanitize=address,undefined','-I',str(edk),'-I',str(edk/'X64'),'-I',str(data),str(p),'-o',str(exe)],check=True);subprocess.run([str(exe)],check=True)

