// SPDX-License-Identifier: BSD-2-Clause-Patent
// Execute production C2 lifecycle with a mock monitor, never a real SMC.
#define _POSIX_C_SOURCE 200112L
#define FUXI_M3_SMCI_ROOT 1
#define FUXI_M3_SCM_BRIDGE_CALL 1
#define FUXI_M3_BRIDGE_BLOB 0
#include "DataReadOnly.h"
#include <Library/ArmSmcLib.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define FNU_STAGE(N) ((void)(N))
static UINT8 *Page;
static int Calls,Frees,Mode,mOps;
static void *ZeroMem(void *p,UINTN n){return memset(p,0,n);}
static void FnuLog(CONST CHAR16 *f,...){(void)f;}
static void FnuCacheCiv(void *ops,void *p,UINTN n){(void)ops;assert(p==Page && n==8192);}
static void FnuCacheInv(void *ops,void *p,UINTN n){(void)ops;assert(p==Page && n==8192);}
static EFI_STATUS AllocatePages(int t,int m,UINTN n,EFI_PHYSICAL_ADDRESS *p){
 (void)t;(void)m;assert(n==2 && !Page);
 if(Mode==1)return EFI_OUT_OF_RESOURCES;
 assert(posix_memalign((void **)&Page,4096,8192)==0);*p=(UINTN)Page;return EFI_SUCCESS;
}
static EFI_STATUS FreePages(EFI_PHYSICAL_ADDRESS raw,UINTN n){
 assert((UINTN)Page==raw && n==2);
 for(UINTN i=0;i<8192;++i)assert(!Page[i]);
 ++Frees;free(Page);Page=NULL;return EFI_SUCCESS;
}
static struct {EFI_STATUS (*AllocatePages)(int,int,UINTN,EFI_PHYSICAL_ADDRESS *);
 EFI_STATUS (*FreePages)(EFI_PHYSICAL_ADDRESS,UINTN);} Boot={AllocatePages,FreePages},*gBS=&Boot;
static UINT32 Get(const UINT8 *p){return p[0]|((UINT32)p[1]<<8)|((UINT32)p[2]<<16)|((UINT32)p[3]<<24);}
VOID EFIAPI ArmCallSmc(ARM_SMC_ARGS *a){
 ++Calls;assert(Calls<=5);
 UINT64 fn=a->Arg0;
 if(Calls==1)assert(fn==0x42000c1c && a->Arg1==0);
 else if(Calls==2)assert(fn==0x42000c1e && a->Arg1==4 && a->Arg2==((UINTN)Page|(FUXI_M3_BRIDGE_HLOS?6:0)) && a->Arg3==((UINTN)Page|6) && a->Arg4==(8192|(FUXI_M3_BRIDGE_HLOS?0x200:0)) && a->Arg5==(FUXI_M3_BRIDGE_HLOS?3:0));
 else if(Calls==3 || Calls==4){
   assert(fn==(FUXI_M3_SMCI_OBJECT ? 0x72000602 : 0x72000600) && a->Arg1==0x224 && a->Arg2==(UINTN)Page && a->Arg3==4096 && a->Arg4==(UINTN)(Page+4096) && a->Arg5==4096 && !a->Arg6 && !a->Arg7);
   assert(Get(Page)==(Calls==3?1:0x44));
   assert(Get(Page+4)==(Calls==3?5:0xffff) && Get(Page+8)==(Calls==3?0x1100:0));
   for(UINTN i=12;i<8192;++i)assert(!Page[i]);
 }else assert(fn==0x42000c1d && a->Arg1==1 && a->Arg2==(Mode==31?0x123456780000005cULL:0x5c));
 a->Arg0=a->Arg1=a->Arg2=a->Arg3=0;
 if(Calls==1 && Mode==2)a->Arg0=1;
 if(Calls==1 && Mode==28)a->Arg1=4;
 if(Calls==1 && Mode==36)a->Arg1=0x100000000ULL;
 if(Calls==2){a->Arg2=Mode==31?0x123456780000005cULL:0x5c;if(Mode==3)a->Arg0=1;
   if(Mode==29){a->Arg1=0x5c;a->Arg2=0;}
   if(Mode==30)a->Arg2=0;
   if(Mode==32){a->Arg0=1;Page[137]=0xa5;}
 }
 if(Calls==3){
   Page[20]=0x44;
   Page[4096]=2;Page[4098]=1;Page[4100]=0xfd;Page[4101]=0xff; // version/op, counts 0.
   if(Mode==33){a->Arg0=1;Page[8191]=0xa5;}
   if(Mode==27)a->Arg0=0xffffffff80000001ULL; // Observed v1 raw failure.
   if(Mode==4)a->Arg0=1; // Interrupted: no resumption implemented.
   if(Mode==5)a->Arg0=2; // Wait queue: no polling or guessing.
   if(Mode==6)a->Arg0=0xffffffffffffffffULL;
   if(Mode==7)a->Arg1=3; // Callback.
   if(Mode==8)a->Arg1=1; // Listener/incomplete.
   if(Mode==9)a->Arg1=0x100;
   if(Mode==10)a->Arg2=0xfffffffeU;
   if(Mode==11)a->Arg3=1;
   if(Mode==12)Page[20]=0;
   if(Mode==13)Page[20]=1;
   if(Mode==14)Page[23]=0x80;
   if(Mode==15)Page[24]=1;
   if(Mode==16)Page[0]=2;
   if(Mode==17)Page[12]=1;
   if(Mode==18)Page[4095]=1;
   if(Mode==19)Page[4108]=1;
   if(Mode==20)Page[8191]=1;
 }
 if(Calls==4){
   Page[4096]=2;Page[4098]=1;Page[4100]=0xfd;Page[4101]=0xff; // version/op, counts 0.
   if(Mode==34){a->Arg0=1;Page[8191]=0xa5;}
   if(Mode==21)a->Arg0=1;
   if(Mode==22)a->Arg1=3;
   if(Mode==23)a->Arg2=1;
   if(Mode==24)Page[12]=1;
   if(Mode==25)Page[4108]=1;
 }
 if(Calls==5){a->Arg1=0x59;if(Mode==26)a->Arg0=1;if(Mode==35){a->Arg0=1;Page[137]=0xa5;}}
}
#include "M3BridgeDiagnostic.inc"
#include "M3SmciDiagnostic.inc"
int main(void){
 for(Mode=0;Mode<=36;++Mode){
   Calls=Frees=0;assert(!Page);FnuSmciRootProbe();
   if(Mode==0 || Mode==31)assert(Calls==5 && Frees==1 && !Page && mSmciStatus==EFI_SUCCESS);
   else if(Mode==1)assert(Calls==0 && Frees==0 && !Page && mSmciStatus==EFI_OUT_OF_RESOURCES);
   else if(Mode==2 || Mode==28 || Mode==36)assert(Calls==1 && Frees==1 && !Page && EFI_ERROR(mSmciStatus));
   else {
     int expected=Mode==29 || Mode==30 || Mode==32?2:Mode==33?3:Mode==34?4:Mode==35?5:Mode==27?3:Mode==3?2:Mode<=20?3:Mode<=25?4:5;
     assert(Calls==expected && Frees==0 && Page && EFI_ERROR(mSmciStatus));
     if(Mode==32 || Mode==35)assert(Page[137]==0xa5);
     if(Mode==33 || Mode==34)assert(Page[8191]==0xa5);
     free(Page);Page=NULL; // Test teardown only; firmware retains this memory.
   }
 }
 puts("PASS 37 C2 production lifecycle vectors: no key, no device, simulated SMC");return 0;
}
