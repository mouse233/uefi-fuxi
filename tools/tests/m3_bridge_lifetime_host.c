// SPDX-License-Identifier: BSD-2-Clause-Patent
// Production bridge-only lifecycle with a mock monitor and 64-bit handles.
#define _POSIX_C_SOURCE 200112L
#define FUXI_M3_SCM_BRIDGE_CALL 1
#define FUXI_M3_BRIDGE_BLOB 0
#define FUXI_M3_SMCI_ROOT 0
#include "DataReadOnly.h"
#include <Library/ArmSmcLib.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define FNU_STAGE(N) ((void)(N))
static unsigned char *Page;
static int Mode,Calls,Frees,mOps;
static void *ZeroMem(void *p,UINTN n){return memset(p,0,n);}
static void FnuLog(CONST CHAR16 *f,...){(void)f;}
static void FnuCacheCiv(void *ops,void *p,UINTN n){(void)ops;assert(p==Page && n==8192);}
static EFI_STATUS AllocatePages(int t,int m,UINTN n,EFI_PHYSICAL_ADDRESS *p){
 (void)t;(void)m;assert(n==2 && !Page);if(Mode==1)return EFI_OUT_OF_RESOURCES;
 assert(posix_memalign((void **)&Page,4096,8192)==0);*p=(UINTN)Page;return EFI_SUCCESS;
}
static EFI_STATUS FreePages(EFI_PHYSICAL_ADDRESS p,UINTN n){
 assert(p==(UINTN)Page && n==2);for(UINTN i=0;i<8192;++i)assert(!Page[i]);
 ++Frees;free(Page);Page=NULL;return EFI_SUCCESS;
}
static struct {EFI_STATUS (*AllocatePages)(int,int,UINTN,EFI_PHYSICAL_ADDRESS *);
 EFI_STATUS (*FreePages)(EFI_PHYSICAL_ADDRESS,UINTN);} Boot={AllocatePages,FreePages},*gBS=&Boot;
VOID EFIAPI ArmCallSmc(ARM_SMC_ARGS *a){
 ++Calls;assert(Calls<=3);assert(!a->Arg6 && !a->Arg7);
 if(Calls==1)assert(a->Arg0==0x42000c1c && !a->Arg1 && !a->Arg2);
 if(Calls==2)assert(a->Arg0==0x42000c1e && a->Arg1==4 && a->Arg2==(UINTN)Page && a->Arg3==((UINTN)Page|6) && a->Arg4==8192 && !a->Arg5);
 if(Calls==3){assert(a->Arg0==0x42000c1d && a->Arg1==1 && a->Arg2==0x10000005cULL);for(UINTN i=0;i<8192;++i)assert(!Page[i]);}
 a->Arg0=a->Arg1=a->Arg2=a->Arg3=0;
 if(Calls==1){if(Mode==2)a->Arg0=1;if(Mode==3)a->Arg1=4;}
 if(Calls==2){
   a->Arg2=0x10000005cULL;
   if(Mode==4)a->Arg0=0xffffffff80000001ULL;
   if(Mode==5){a->Arg1=0x5c;a->Arg2=0;}
   if(Mode==6)a->Arg2=0;
   if(Mode==8)a->Arg0=1;
   if(Mode==10){a->Arg1=1;Page[137]=0xa5;}
 }
 if(Calls==3){
   if(Mode==7)a->Arg0=1;
   if(Mode==9)a->Arg1=0x59; // Fixed delete wrapper consumes only a0.
   if(Mode==11){a->Arg0=2;Page[137]=0xa5;}
 }
}
#include "M3BridgeDiagnostic.inc"
int main(void){
 for(Mode=0;Mode<12;++Mode){
   Calls=Frees=0;assert(!Page);FnuBridgeCallProbe(NULL,NULL,NULL,NULL);
   if(Mode==0 || Mode==9)assert(Calls==3 && Frees==1 && !Page);
   else if(Mode==1)assert(!Calls && !Frees && !Page);
   else if(Mode==2 || Mode==3)assert(Calls==1 && Frees==1 && !Page);
   else {assert(Calls==((Mode==7 || Mode==11)?3:2) && !Frees && Page);
     if(Mode==10 || Mode==11)assert(Page[137]==0xa5); // Unknown ownership: no wipe.
     free(Page);Page=NULL; // Host-only teardown, firmware retains.
   }
 }
 puts("PASS 12 production standard bridge lifetime vectors");return 0;
}
