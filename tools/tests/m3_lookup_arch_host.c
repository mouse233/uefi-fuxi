// SPDX-License-Identifier: BSD-2-Clause-Patent
// Actual deployed-ABI production batch, synthetic monitor/filesystem only.
#define _POSIX_C_SOURCE 200112L
#define FUXI_M3_SMCI_ROOT 1
#define FUXI_M3_SMCI_LOADER 1
#define FUXI_M3_SMCI_LOOKUP 1
#define FUXI_M3_SMCI_LOOKUP_ARCH 1
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
static UINT8 *Page;static int Mode,Calls,Frees,LogCalls,mOps;static FNU_REPORT Report;
static void *ZeroMem(void *p,UINTN n){return memset(p,0,n);}
static void FnuLog(CONST CHAR16 *f,...){++LogCalls;FnuReportAppend(&Report,f);}
static void FnuCacheCiv(void *o,void *p,UINTN n){(void)o;assert(p==Page&&n==8192);}
static void FnuCacheInv(void *o,void *p,UINTN n){(void)o;assert(p==Page&&n==8192);}
static EFI_STATUS AllocatePages(int t,int m,UINTN n,EFI_PHYSICAL_ADDRESS *p){
 (void)t;(void)m;assert(n==2&&!Page);if(Mode==33)return EFI_OUT_OF_RESOURCES;
 assert(!posix_memalign((void**)&Page,4096,8192));*p=(UINTN)Page;return EFI_SUCCESS;
}
static EFI_STATUS FreePages(EFI_PHYSICAL_ADDRESS p,UINTN n){
 assert(p==(UINTN)Page&&n==2);for(UINTN i=0;i<8192;++i)assert(!Page[i]);
 ++Frees;free(Page);Page=NULL;return EFI_SUCCESS;
}
static struct {EFI_STATUS (*AllocatePages)(int,int,UINTN,EFI_PHYSICAL_ADDRESS*);EFI_STATUS (*FreePages)(EFI_PHYSICAL_ADDRESS,UINTN);} Boot={AllocatePages,FreePages},*gBS=&Boot;
static void Put(UINT8*p,UINT32 n){for(UINTN i=0;i<4;++i)p[i]=(UINT8)(n>>(8*i));}
static int ErrorOnly(void){return Mode==2||Mode==3;}
VOID EFIAPI ArmCallSmc(ARM_SMC_ARGS*a){
 ++Calls;assert(Calls<=9);UINT64 fn=a->Arg0;int kind=Calls;
 if(Calls>=6&&ErrorOnly())kind=Calls+1; // clean error: no TA object to release
 if(kind==1)assert(fn==0x42000c1c&&a->Arg1==0);
 else if(kind==2)assert(fn==0x42000c1e&&a->Arg1==4&&a->Arg2==((UINTN)Page|6)&&a->Arg3==((UINTN)Page|6)&&a->Arg4==0x2200&&a->Arg5==3);
 else if(kind==9)assert(fn==0x42000c1d&&a->Arg1==1&&a->Arg2==0x5c);
 else {
  assert(fn==0x72000602&&a->Arg1==0x224&&a->Arg2==(UINTN)Page&&a->Arg3==4096&&a->Arg4==(UINTN)(Page+4096)&&a->Arg5==4096&&!a->Arg6&&!a->Arg7);
  UINT8 expected[8192]={0};
  if(kind==3){Put(expected,1);Put(expected+4,5);Put(expected+8,0x1100);}
  else if(kind==4){Put(expected,2);Put(expected+8,0x1001);Put(expected+12,32);Put(expected+16,4);Put(expected+32,122);}
  else if(kind==5){
   Put(expected,3);Put(expected+4,2);Put(expected+8,0x1011);Put(expected+12,40);Put(expected+16,11);
   Put(expected+20,56);Put(expected+24,4);memcpy(expected+40,"keymaster64",11);
  }else {Put(expected,kind==6?4:kind==7?3:2);Put(expected+4,0xffff);}
  assert(!memcmp(Page,expected,8192));
 }
 a->Arg0=a->Arg1=a->Arg2=a->Arg3=0;
 if(kind==2)a->Arg2=0x5c;
 if(kind==3)Put(Page+20,2);
 if(kind==4)Put(Page+20,3);
 if(kind>=3&&kind<=8){Put(Page+4096,0x10002);Put(Page+4100,Mode==1?0xffff:0xfffd);}
 if(kind==5){
  if(ErrorOnly())a->Arg2=Mode==2?2:23;
  else {Put(Page+28,4);Put(Page+56,Mode==1?1:2);}
  switch(Mode){
   case 4:a->Arg0=1;break;case 5:a->Arg1=1;break;case 6:a->Arg3=1;break;
   case 7:Page[0]^=1;break;case 8:Page[4]^=1;break;case 9:Page[8]^=1;break;
   case 10:Page[12]^=1;break;case 11:Page[16]^=1;break;case 12:Page[20]^=1;break;
   case 13:Put(Page+24,3);break;case 14:Put(Page+28,0);break;case 15:Put(Page+28,1);break;
   case 16:Put(Page+28,0x80000004U);break;case 17:Page[32]=1;break;
   case 18:Put(Page+56,0);break;case 19:Put(Page+56,3);break;case 20:Page[40]^=1;break;
   case 21:Page[36]=1;break;case 22:Page[61]=1;break;case 23:Page[4104]=1;break;
   case 24:a->Arg2=2;Put(Page+56,0);break; // error returned a capability
   case 25:a->Arg2=2;Put(Page+28,0);break; // error returned architecture
   case 26:a->Arg2=2;Put(Page+28,0);Put(Page+56,0);Page[40]^=1;break;
   case 27:Put(Page+4096,0x1234);break;case 28:Put(Page+56,4);break;
   case 34:Put(Page+28,2);break;case 35:Put(Page+28,3);break;
   case 36:Put(Page+4096,0);Put(Page+4100,0);break;
  }
 }
 if(Mode>=29&&Mode<=32&&kind==Mode-23)a->Arg0=1;
}
#include "M3BridgeDiagnostic.inc"
#include "M3SmciDiagnostic.inc"
int main(void){
 for(Mode=0;Mode<=36;++Mode){
  Calls=Frees=LogCalls=0;assert(!Page);memset(&Report,0,sizeof(Report));
  for(int i=0;i<128;++i)FnuReportAppend(&Report,L"pre-M3 public baseline");
  FnuSmciRootProbe();assert(!Report.Dropped&&!Report.Truncated&&Report.Count==(UINTN)(128+LogCalls));
  if(Mode<=1||Mode==36)assert(Calls==9&&Frees==1&&!Page&&mSmciStatus==EFI_SUCCESS);
  else if(ErrorOnly())assert(Calls==8&&Frees==1&&!Page&&mSmciStatus==EFI_NOT_FOUND);
  else if(Mode==33)assert(!Calls&&!Frees&&!Page&&mSmciStatus==EFI_OUT_OF_RESOURCES);
  else if(Mode>=29&&Mode<=32)assert(Calls==Mode-23&&!Frees&&Page&&EFI_ERROR(mSmciStatus));
  else assert(Calls==5&&!Frees&&Page&&EFI_ERROR(mSmciStatus));
  if(Page){free(Page);Page=NULL;} // fake host allocation teardown only
 }
 // The new diagnostic must never issue the old fallback name.
 UINT8 page[8192]={0};UINT32 object=0;
 assert(SmciInvoke((UINTN)page,page,sizeof(page),3,4,&object)==EFI_INVALID_PARAMETER);
 puts("PASS 38 deployed lookup cases; strict replies, no fallback/load/TA commands; monitor simulated");
 return 0;
}
