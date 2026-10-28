// SPDX-License-Identifier: BSD-2-Clause-Patent
// Production gated C2/C3 load stage; monitor is simulated, never a real SMC.
#define _POSIX_C_SOURCE 200112L
#define FUXI_M3_BRIDGE_LARGE 1
#define TEST_PAGES 130
#define TEST_BYTES (TEST_PAGES * 4096)
#define TA_BYTES 0x63058U
#define TA_PAGES 100U
#define TA_ALLOC (TA_PAGES * 4096)
#define FUXI_M3_SMCI_ROOT 1
#define FUXI_M3_SMCI_LOADER 1
#define FUXI_M3_SMCI_LOOKUP 0
#define FUXI_M3_SMCI_LOAD 1
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
static UINT8 *Page, *TaBuf;
static UINTN mTaImageBytes, mTaImagePages;
static UINT8 *mTaImage;
static int Calls,Frees,TaFrees,Phase,Fault,Special,mOps,LogCalls;
static FNU_REPORT Report;
static void *ZeroMem(void *p,UINTN n){return memset(p,0,n);}
static void *CopyMem(void *d,const void *s,UINTN n){return memcpy(d,s,n);}
static void FnuLog(CONST CHAR16 *f,...){++LogCalls;FnuReportAppend(&Report,f);}
static void FnuCacheCiv(void *ops,void *p,UINTN n){(void)ops;assert(p==Page && (n==8192 || n==TEST_BYTES));}
static void FnuCacheInv(void *ops,void *p,UINTN n){(void)ops;assert(p==Page && (n==8192 || n==TEST_BYTES));}
static EFI_STATUS AllocatePages(int t,int m,UINTN n,EFI_PHYSICAL_ADDRESS *p){
 (void)t;(void)m;
 if(Phase==99)return EFI_OUT_OF_RESOURCES;
 assert(n==TEST_PAGES && !Page);
 assert(posix_memalign((void **)&Page,4096,TEST_BYTES)==0);*p=(UINTN)Page;return EFI_SUCCESS;
}
static EFI_STATUS FreePages(EFI_PHYSICAL_ADDRESS raw,UINTN n){
 if (n==TA_PAGES) {
   assert((UINTN)TaBuf==raw);
   for(UINTN i=0;i<TA_ALLOC;++i)assert(!TaBuf[i]);
   ++TaFrees;free(TaBuf);TaBuf=NULL;mTaImage=NULL;mTaImageBytes=0;mTaImagePages=0;
   return EFI_SUCCESS;
 }
 assert(n==TEST_PAGES && (UINTN)Page==raw);
 for(UINTN i=0;i<TEST_BYTES;++i)assert(!Page[i]);
 ++Frees;
 free(Page);Page=NULL;return EFI_SUCCESS;
}
static struct {EFI_STATUS (*AllocatePages)(int,int,UINTN,EFI_PHYSICAL_ADDRESS *);
 EFI_STATUS (*FreePages)(EFI_PHYSICAL_ADDRESS,UINTN);} Boot={AllocatePages,FreePages},*gBS=&Boot;
static void Put(UINT8 *p,UINT32 v){for(UINTN i=0;i<4;++i)p[i]=(UINT8)(v>>(8*i));}
static UINT32 Loader(void){return Special==2?0x44:0x88;}
static UINT32 App(void){return 0xa0;}
static UINT64 Bridge(void){return Special==1?0x123456780000005cULL:0x5c;}
static UINT8 *OutPage(void){return Page+TEST_BYTES-4096;}
VOID EFIAPI ArmCallSmc(ARM_SMC_ARGS *a){
 ++Calls;assert(Calls<=9);
 UINT64 fn=a->Arg0;
 if(Calls==1)assert(fn==0x42000c1c && a->Arg1==0);
 else if(Calls==2)assert(fn==0x42000c1e && a->Arg1==4 && a->Arg2==((UINTN)Page|6) && a->Arg3==((UINTN)Page|6) && a->Arg4==(TEST_BYTES|0x200) && a->Arg5==3);
 else if(Calls>=3&&Calls<=5){
   // The load message is the only one that spans the bridge; its out page sits
   // in the last page, so the two ranges must not overlap.
   UINT32 in_len=Calls==5?0x630d8U:4096U;
   UINT8 *out=Calls==5?OutPage():Page+4096;
   assert(fn==0x72000602 && a->Arg1==0x224 && a->Arg2==(UINTN)Page && a->Arg3==in_len
          && a->Arg4==(UINTN)out && a->Arg5==4096 && !a->Arg6 && !a->Arg7);
   assert((UINTN)(Page+in_len) <= (UINTN)out);
   if(Calls==3){
     assert(*((UINT32*)(Page+0))==1 && *((UINT32*)(Page+4))==5 && *((UINT32*)(Page+8))==0x1100);
   } else if(Calls==4){
     assert(*((UINT32*)(Page+0))==0x44 && *((UINT32*)(Page+4))==0 && *((UINT32*)(Page+8))==0x1001);
     assert(*((UINT32*)(Page+12))==32 && *((UINT32*)(Page+16))==4 && *((UINT32*)(Page+32))==122);
   } else {
     // loadFromBuffer: BI2/BO1/OO1, payload at 48, name after the image, then
     // the 64-byte distName buffer.
     assert(*((UINT32*)(Page+0))==Loader());
     assert(*((UINT32*)(Page+4))==1 && *((UINT32*)(Page+8))==0x1012);
     assert(*((UINT32*)(Page+12))==48 && *((UINT32*)(Page+16))==TA_BYTES);
     assert(*((UINT32*)(Page+20))==48+TA_BYTES && *((UINT32*)(Page+24))==11);
     assert(*((UINT32*)(Page+28))==(48+TA_BYTES+11+7)/8*8 && *((UINT32*)(Page+32))==64);
     assert(!memcmp(Page+48,TaBuf,TA_BYTES));
     assert(!memcmp(Page+48+TA_BYTES,"keymaster64",11));
   }
 } else if(Calls<=8){
   UINT32 obj=(Calls==6)?App():(Calls==7)?Loader():0x44;
   assert(fn==0x72000602 && a->Arg1==0x224 && a->Arg2==(UINTN)Page && a->Arg3==4096
          && a->Arg4==(UINTN)(Page+4096) && a->Arg5==4096 && !a->Arg6 && !a->Arg7);
   assert(*((UINT32*)(Page+0))==obj && *((UINT32*)(Page+4))==0xffff && *((UINT32*)(Page+8))==0);
 } else {
   // Bridge delete is the last call; its service word is not consumed.
   assert(fn==0x42000c1d && a->Arg1==1 && a->Arg2==Bridge());
 }
 a->Arg0=a->Arg1=a->Arg2=a->Arg3=0;
 if(Calls==2)a->Arg2=Bridge();
 if(Calls==3)Put(Page+20,0x44);
 if(Calls==4)Put(Page+20,Loader());
 if(Calls==5)Put(Page+36,App());
 // The device returned a non-empty out page: version/op only, counts zero.
 if(Calls>=3&&Calls<=5){UINT8 *o=(Calls==5)?OutPage():Page+4096;Put(o,0x00010002);Put(o+4,0x0000fffd);}
 if(Calls==9)a->Arg1=0x59;
 if(Calls!=Phase)return;
 switch(Fault){
 case 0:break;
 case 1:if(Calls==1||Calls==2||Calls==9)a->Arg0=1;else a->Arg2=2;break;
 case 2:a->Arg1=3;break;
 case 3:a->Arg2=0;break;                                  // create decode
 case 4:Put(Page+36,0);break;                             // no app object
 case 5:Put(Page+36,0x800000a0U);break;                   // tagged handle
 case 6:Page[16]^=1;break;                                // BI size tampered
 case 7:Page[TEST_BYTES-4096+12]=1;break;                 // out page dirty
 case 8:Put(Page+12,49);break;                            // ELF offset tampered
 case 9:a->Arg3=1;break;                                  // extra out register
 case 10:Put(Page+0,0x99);break;                          // handle echoed wrong
 default:assert(0);
 }
}
#include "M3BridgeDiagnostic.inc"
#include "M3SmciDiagnostic.inc"
static void SetupTa(void){
 assert(posix_memalign((void **)&TaBuf,4096,TA_ALLOC)==0);
 for(UINTN i=0;i<TA_ALLOC;++i)TaBuf[i]=(UINT8)(i*7+3);
 mTaImage=TaBuf;mTaImageBytes=TA_BYTES;mTaImagePages=TA_PAGES;
}
static int Vectors,MaxLogCalls;
static void Run(int phase,int fault){
 Phase=phase;Fault=fault;Special=0;Calls=Frees=TaFrees=LogCalls=0;assert(!Page);assert(!TaBuf);
 SetupTa();
 memset(&Report,0,sizeof(Report));
 for(int i=0;i<128;++i)FnuReportAppend(&Report,L"synthetic pre-M3 baseline");
 FnuSmciRootProbe();++Vectors;
 assert(!Report.Dropped && !Report.Truncated && Report.Count==(UINTN)(128+LogCalls));
 if(LogCalls>MaxLogCalls)MaxLogCalls=LogCalls;
 assert(TaFrees==1 && !TaBuf && !mTaImage);
 if(!phase)assert(Calls==9 && Frees==1 && !Page && mSmciStatus==EFI_SUCCESS);
 else if(phase==1&&fault==1)assert(Calls==1 && Frees==1 && !Page && EFI_ERROR(mSmciStatus));
 else if(phase==1&&fault==2)assert(Calls==1 && Frees==1 && !Page && EFI_ERROR(mSmciStatus));
 else {
   if(!(Calls==phase && !Frees && Page && EFI_ERROR(mSmciStatus))){
     fprintf(stderr,"phase %d fault %d calls=%d frees=%d page=%p status=%llx\n",
             phase,fault,Calls,Frees,(void*)Page,(unsigned long long)mSmciStatus);
     abort();
   }
   free(Page);Page=NULL; // Host teardown only; production must retain.
 }
}
static void RunNoImage(void){
 Phase=0;Fault=0;Special=0;Calls=Frees=TaFrees=LogCalls=0;assert(!Page);assert(!TaBuf);
 memset(&Report,0,sizeof(Report));
 FnuSmciRootProbe();++Vectors;
 // Allocation succeeds, bridge is built, then the load stage refuses to run
 // without an image: the batch stops at loader-load and retains everything.
 assert(Calls==4 && !Frees && Page && TaFrees==0 && EFI_ERROR(mSmciStatus));
 free(Page);Page=NULL;
}
static void RunAllocFail(void){
 Phase=99;Fault=0;Special=0;Calls=Frees=TaFrees=LogCalls=0;assert(!Page);assert(!TaBuf);
 SetupTa();
 memset(&Report,0,sizeof(Report));
 FnuSmciRootProbe();++Vectors;
 assert(!Calls && !Frees && !Page && TaFrees==1 && !TaBuf && mSmciStatus==EFI_OUT_OF_RESOURCES);
}
int main(void){
 Run(0,0);
 RunAllocFail();
 RunNoImage();
 Run(1,1);Run(1,2);
 Run(2,1);Run(2,2);Run(2,3);
 Run(3,1);Run(4,1);
 for(int f=1;f<=10;++f)if(f!=3)Run(5,f);
 for(int p=6;p<=9;++p)Run(p,1);
 assert(Vectors==23);
 printf("PASS %d load-stage vectors; max batch logs=%d; simulated monitor only\n",Vectors,MaxLogCalls);
 return 0;
}
