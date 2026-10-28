// SPDX-License-Identifier: BSD-2-Clause-Patent
// Production gated C2/C3 lifecycle; monitor is simulated, never a real SMC.
#define _POSIX_C_SOURCE 200112L
#ifndef FUXI_M3_BRIDGE_LARGE
#define FUXI_M3_BRIDGE_LARGE 0
#endif
#define TEST_PAGES (FUXI_M3_BRIDGE_LARGE ? 130 : 2)
#define TEST_BYTES (TEST_PAGES * 4096)
#define FUXI_M3_SMCI_ROOT 1
#define FUXI_M3_SMCI_LOADER 1
#define FUXI_M3_SMCI_OBJECT 1
#define FUXI_M3_BRIDGE_HLOS 1
#define FUXI_M3_SCM_BRIDGE_CALL 1
#define FUXI_M3_BRIDGE_BLOB 0
#include "DataReadOnly.h"
#include "UfsReport.h"
#include <Library/ArmSmcLib.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define FNU_STAGE(N) ((void)(N))
static UINT8 *Page;
static int Calls,Frees,Phase,Fault,Special,mOps,LogCalls;
static FNU_REPORT Report;
static void *ZeroMem(void *p,UINTN n){return memset(p,0,n);}
static void FnuLog(CONST CHAR16 *f,...){++LogCalls;FnuReportAppend(&Report,f);}
static void FnuCacheCiv(void *ops,void *p,UINTN n){(void)ops;assert(p==Page && (n==8192 || n==TEST_BYTES));}
static void FnuCacheInv(void *ops,void *p,UINTN n){(void)ops;assert(p==Page && (n==8192 || n==TEST_BYTES));}
static EFI_STATUS AllocatePages(int t,int m,UINTN n,EFI_PHYSICAL_ADDRESS *p){
 (void)t;(void)m;assert(n==TEST_PAGES && !Page);
 if(Phase==8)return EFI_OUT_OF_RESOURCES;
 assert(posix_memalign((void **)&Page,4096,TEST_BYTES)==0);*p=(UINTN)Page;return EFI_SUCCESS;
}
static EFI_STATUS FreePages(EFI_PHYSICAL_ADDRESS raw,UINTN n){
 assert((UINTN)Page==raw && n==TEST_PAGES);
 for(UINTN i=0;i<TEST_BYTES;++i)assert(!Page[i]);
 ++Frees;free(Page);Page=NULL;return EFI_SUCCESS;
}
static struct {EFI_STATUS (*AllocatePages)(int,int,UINTN,EFI_PHYSICAL_ADDRESS *);
 EFI_STATUS (*FreePages)(EFI_PHYSICAL_ADDRESS,UINTN);} Boot={AllocatePages,FreePages},*gBS=&Boot;
static void Put(UINT8 *p,UINT32 v){for(UINTN i=0;i<4;++i)p[i]=(UINT8)(v>>(8*i));}
static UINT32 Loader(void){return Special==2?0x44:0x88;}
static UINT64 Bridge(void){return Special==1?0x123456780000005cULL:0x5c;}
VOID EFIAPI ArmCallSmc(ARM_SMC_ARGS *a){
 ++Calls;assert(Calls<=7);
 UINT64 fn=a->Arg0;
 if(Calls==1)assert(fn==0x42000c1c && a->Arg1==0);
 else if(Calls==2)assert(fn==0x42000c1e && a->Arg1==4 && a->Arg2==((UINTN)Page|6) && a->Arg3==((UINTN)Page|6) && a->Arg4==(TEST_BYTES|0x200) && a->Arg5==3);
 else if(Calls<=6){
   assert(fn==0x72000602 && a->Arg1==0x224 && a->Arg2==(UINTN)Page && a->Arg3==4096 && a->Arg4==(UINTN)(Page+4096) && a->Arg5==4096 && !a->Arg6 && !a->Arg7);
   UINT8 expected[8192]={0};
   Put(expected,Calls==3?1:Calls==5?Loader():0x44);
   Put(expected+4,Calls==3?5:Calls==4?0:0xffff);
   Put(expected+8,Calls==3?0x1100:Calls==4?0x1001:0);
   if(Calls==4){Put(expected+12,32);Put(expected+16,4);Put(expected+32,122);}
   assert(!memcmp(Page,expected,8192));
 }else assert(fn==0x42000c1d && a->Arg1==1 && a->Arg2==Bridge());
 a->Arg0=a->Arg1=a->Arg2=a->Arg3=0;
 if(Calls==2)a->Arg2=Bridge();
 if(Calls==3)Put(Page+20,0x44);
 if(Calls==4)Put(Page+20,Loader());
 // The device returned a non-empty out page: version/op only, counts zero.
 if(Calls>=3&&Calls<=6){Put(Page+4096,0x00010002);Put(Page+4100,0x0000fffd);}
 // Delete service a1 is not consumed by the fixed wrapper; only SCM a0.
 if(Calls==7)a->Arg1=0x59;
 if(Calls!=Phase)return;
 if(Phase==1){if(Fault==1)a->Arg0=1;else a->Arg1=Fault==2?4:0x100000000ULL;return;}
 if(Phase==2){
   if(Fault==1)a->Arg0=1;
   if(Fault==2){a->Arg1=0x5c;a->Arg2=0;}
   if(Fault==3)a->Arg2=0;
   if(Fault==4){a->Arg0=1;Page[137]=0xa5;}
   return;
 }
 if(Phase==7){a->Arg0=1;if(Fault==2)Page[137]=0xa5;return;}
 switch(Fault){
 case 1:a->Arg0=1;break;
 case 2:a->Arg1=3;break;
 case 3:a->Arg2=0xfffffffeU;break;
 case 4:a->Arg3=1;break;
 case 5:Page[0]^=1;break;
 case 6:Page[4]^=1;break;
 case 7:Page[8]^=1;break;
 case 8:Page[12]^=1;break;
 case 9:Page[4095]=1;break;
 case 22:Put(Page+4104,1);break;
 case 23:Page[4108]=1;break;
 case 11:a->Arg0=0xffffffff80000001ULL;Page[8191]=0xa5;break;
 case 12:Page[24]=1;break;
 case 13:Page[8191]=1;break;
 case 14:Put(Page+20,0);break;
 case 15:Put(Page+20,1);break;
 case 16:Put(Page+20,0x80000044);break;
 case 17:Put(Page+24,1);break;
 case 18:Put(Page+20,0);Page[137]=0xa5;break;
 case 19:Put(Page+16,0);break;
 case 20:Put(Page+32,123);break;
 case 21:Page[28]=1;break;
 default:assert(0);
 }
}
#include "M3BridgeDiagnostic.inc"
#include "M3SmciDiagnostic.inc"
static int Vectors,MaxLogCalls;
static void Run(int phase,int fault,int special){
 Phase=phase;Fault=fault;Special=special;Calls=Frees=LogCalls=0;assert(!Page);
 memset(&Report,0,sizeof(Report));
 // Retain 128 pre-M3 lines and execute actual production log paths. The old
 // cache would overflow; the batch cache must retain every later checkpoint.
 for(int i=0;i<128;++i)FnuReportAppend(&Report,L"synthetic pre-M3 baseline");
 FnuSmciRootProbe();++Vectors;
 assert(!Report.Dropped && !Report.Truncated && Report.Count==(UINTN)(128+LogCalls));
 if(LogCalls>MaxLogCalls)MaxLogCalls=LogCalls;
 if(!phase)assert(Calls==7 && Frees==1 && !Page && mSmciStatus==EFI_SUCCESS);
 else if(phase==8)assert(!Calls && !Frees && !Page && mSmciStatus==EFI_OUT_OF_RESOURCES);
 else if(phase==1)assert(Calls==1 && Frees==1 && !Page && EFI_ERROR(mSmciStatus));
 else {
   assert(Calls==phase && !Frees && Page && EFI_ERROR(mSmciStatus));
   if((phase==2 && fault==4)||(phase==7 && fault==2)||fault==18)assert(Page[137]==0xa5);
   if(phase>=3 && phase<=6 && fault==11)assert(Page[8191]==0xa5);
   free(Page);Page=NULL; // Host teardown only; production must retain.
 }
}
int main(void){
 Run(0,0,0);Run(8,0,0);
 for(int f=1;f<=3;++f)Run(1,f,0);
 for(int f=1;f<=4;++f)Run(2,f,0);
 for(int p=3;p<=6;++p)for(int f=1;f<=13;++f)if(f!=10)Run(p,f,0);
 for(int p=3;p<=6;++p)for(int f=22;f<=23;++f)Run(p,f,0);
 for(int p=3;p<=4;++p)for(int f=14;f<=18;++f)Run(p,f,0);
 for(int f=19;f<=21;++f)Run(4,f,0);
 Run(7,1,0);Run(7,2,0);
 Run(0,0,1);Run(0,0,2); // 64-bit bridge and two owned refs to alias handle.
 assert(Vectors==82);
 printf("PASS %d production C2/C3 vectors; max batch logs=%d plus128 baseline; no hardware\n",Vectors,MaxLogCalls);
 return 0;
}
