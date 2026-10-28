// SPDX-License-Identifier: BSD-2-Clause-Patent
// Production gated lookup batch; monitor is simulated, never a real SMC.
#define _POSIX_C_SOURCE 200112L
#define FUXI_M3_SMCI_ROOT 1
#define FUXI_M3_SMCI_LOADER 1
#define FUXI_M3_SMCI_LOOKUP 1
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
static int Calls,Frees,Mode,LogCalls,mOps;
static FNU_REPORT Report;
static void *ZeroMem(void *p,UINTN n){return memset(p,0,n);}
static void FnuLog(CONST CHAR16 *f,...){++LogCalls;FnuReportAppend(&Report,f);}
static void FnuCacheCiv(void *o,void *p,UINTN n){(void)o;assert(p==Page && n==8192);}
static void FnuCacheInv(void *o,void *p,UINTN n){(void)o;assert(p==Page && n==8192);}
static EFI_STATUS AllocatePages(int t,int m,UINTN n,EFI_PHYSICAL_ADDRESS *p){
 (void)t;(void)m;assert(n==2 && !Page);
 if(Mode==9)return EFI_OUT_OF_RESOURCES;
 assert(posix_memalign((void **)&Page,4096,8192)==0);*p=(UINTN)Page;return EFI_SUCCESS;
}
static EFI_STATUS FreePages(EFI_PHYSICAL_ADDRESS raw,UINTN n){
 assert((UINTN)Page==raw && n==2);
 for(UINTN i=0;i<8192;++i)assert(!Page[i]);
 ++Frees;free(Page);Page=NULL;return EFI_SUCCESS;
}
static struct {EFI_STATUS (*AllocatePages)(int,int,UINTN,EFI_PHYSICAL_ADDRESS *);
 EFI_STATUS (*FreePages)(EFI_PHYSICAL_ADDRESS,UINTN);} Boot={AllocatePages,FreePages},*gBS=&Boot;
static void Put(UINT8 *p,UINT32 v){for(UINTN i=0;i<4;++i)p[i]=(UINT8)(v>>(8*i));}
enum {EN=1,CR,REG,OPEN,LK64,LK32,TA_REL,LD_REL,ENV_REL,DEL};
static int Fallback(void){return Mode==1||Mode==2||Mode==8;}
static int TaFound(void){return Mode==0||Mode==1||Mode==8||Mode==10;}
static int Kind(int n){
 if(n==1)return EN; if(n==2)return CR; if(n==3)return REG; if(n==4)return OPEN;
 if(n==5)return LK64;
 int off=Fallback();
 if(off && n==6)return LK32;
 int m=n-off;
 if(m==6)return TaFound()?TA_REL:LD_REL;
 if(m==7)return TaFound()?LD_REL:ENV_REL;
 if(m==8)return TaFound()?ENV_REL:DEL;
 if(m==9)return DEL;
 assert(0);return 0;
}
VOID EFIAPI ArmCallSmc(ARM_SMC_ARGS *a){
 ++Calls;assert(Calls<=10);
 UINT64 fn=a->Arg0;int k=Kind(Calls);
 if(k==EN)assert(fn==0x42000c1c && a->Arg1==0);
 else if(k==CR)assert(fn==0x42000c1e && a->Arg1==4 && a->Arg2==((UINTN)Page|6) && a->Arg3==((UINTN)Page|6) && a->Arg4==0x2200 && a->Arg5==3);
 else if(k==DEL)assert(fn==0x42000c1d && a->Arg1==1 && a->Arg2==0x5c);
 else {
   assert(fn==0x72000602 && a->Arg1==0x224 && a->Arg2==(UINTN)Page && a->Arg3==4096 && a->Arg4==(UINTN)(Page+4096) && a->Arg5==4096 && !a->Arg6 && !a->Arg7);
   UINT8 e[8192]={0};
   if(k==REG){Put(e,1);Put(e+4,5);Put(e+8,0x1100);}
   else if(k==OPEN){Put(e,2);Put(e+8,0x1001);Put(e+12,32);Put(e+16,4);Put(e+32,122);}
   else if(k==LK64||k==LK32){
     const char *n=(k==LK64)?"keymaster64":"keymaster";
     Put(e,3);Put(e+4,2);Put(e+8,0x1001);Put(e+12,32);Put(e+16,(UINT32)strlen(n));
     memcpy(e+32,n,strlen(n));
   }
   else if(k==TA_REL){Put(e,4);Put(e+4,0xffff);}
   else if(k==LD_REL){Put(e,3);Put(e+4,0xffff);}
   else if(k==ENV_REL){Put(e,2);Put(e+4,0xffff);}
   assert(!memcmp(Page,e,8192));
 }
 a->Arg0=a->Arg1=a->Arg2=a->Arg3=0;
 if(k==CR)a->Arg2=0x5c;
 if(k==REG)Put(Page+20,2);
 if(k==OPEN)Put(Page+20,3);
 if(k==LK64){if(Fallback())a->Arg2=2;else Put(Page+20,4);}
 if(k==LK32){if(Mode==2)a->Arg2=2;else Put(Page+20,4);}
 if(k==TA_REL&&Mode==8)a->Arg0=1;
 if(k==LD_REL&&Mode==10)a->Arg0=1;
 if(k!=EN&&k!=CR&&k!=DEL){Put(Page+4096,0x00010002);Put(Page+4100,0x0000fffd);}
 if(Calls==5){
   if(Mode==3)a->Arg1=3;
   if(Mode==4)Page[4]^=1;
   if(Mode==5)Put(Page+4104,1);
   if(Mode==6)Put(Page+20,0);
   if(Mode==7)a->Arg3=1;
 }
}
#include "M3BridgeDiagnostic.inc"
#include "M3SmciDiagnostic.inc"
static int Vectors,MaxLogCalls;
static void Run(int mode){
 Mode=mode;Calls=Frees=LogCalls=0;assert(!Page);
 memset(&Report,0,sizeof(Report));
 for(int i=0;i<128;++i)FnuReportAppend(&Report,L"synthetic pre-M3 baseline");
 FnuSmciRootProbe();++Vectors;
 assert(!Report.Dropped && !Report.Truncated && Report.Count==(UINTN)(128+LogCalls));
 if(LogCalls>MaxLogCalls)MaxLogCalls=LogCalls;
 if(mode==0)assert(Calls==9 && Frees==1 && !Page && mSmciStatus==EFI_SUCCESS);
 else if(mode==1)assert(Calls==10 && Frees==1 && !Page && mSmciStatus==EFI_SUCCESS);
 else if(mode==2)assert(Calls==9 && Frees==1 && !Page && mSmciStatus==EFI_NOT_FOUND);
 else if(mode==9)assert(!Calls && !Frees && !Page && mSmciStatus==EFI_OUT_OF_RESOURCES);
 else if(mode==8||mode==10)assert(Calls==7 && !Frees && Page && EFI_ERROR(mSmciStatus));
 else assert(Calls==5 && !Frees && Page && EFI_ERROR(mSmciStatus));
 if(Page){free(Page);Page=NULL;}
}
int main(void){
 for(int m=0;m<=10;++m)Run(m);
 assert(Vectors==11);
 printf("PASS %d production lookup vectors; max batch logs=%d plus128 baseline; no hardware\n",Vectors,MaxLogCalls);
 return 0;
}
