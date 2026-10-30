// SPDX-License-Identifier: BSD-2-Clause-Patent
// Production ArmCallSmc adapter + backend/core, with a synthetic monitor only.
#define _GNU_SOURCE
#include "M3SecretExchange.h"
#include <Library/ArmSmcLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
static UINT8 *Page;
static UINTN Calls,Clean,Inv,Interrupts,Attempt;
static int Mode;
static unsigned Cases;
static UINT32 U32(const UINT8 *p){return p[0]|((UINT32)p[1]<<8)|((UINT32)p[2]<<16)|((UINT32)p[3]<<24);}
static void Put(UINT8 *p,UINT32 v){for(UINTN i=0;i<4;i++)p[i]=(UINT8)(v>>(8*i));}
VOID *EFIAPI WriteBackInvalidateDataCacheRange(VOID *p,UINTN n){assert(p==Page&&n==FKM_SHARED_BYTES);Clean++;return p;}
VOID *EFIAPI InvalidateDataCacheRange(VOID *p,UINTN n){assert(p==Page&&n==FKM_SHARED_BYTES);Inv++;return p;}
VOID EFIAPI ArmCallSmc(ARM_SMC_ARGS *a){
  UINT32 cmd=U32(Page+96),bo=U32(Page+52);Calls++;
  assert(a->Arg1==0x224&&a->Arg2==(UINTN)Page&&a->Arg3==FKM_MESSAGE_BYTES&&a->Arg4==(UINTN)(Page+FKM_MESSAGE_BYTES)&&a->Arg5==4096&&a->Arg7==0);
  if(Attempt){assert(a->Arg0==1&&a->Arg6==0x1234000000000000ULL+Attempt);}
  else assert(a->Arg0==0x72000602&&!a->Arg6);
  if(cmd==0x310f&&Attempt<Interrupts){
    ++Attempt;a->Arg0=1;a->Arg6=(UINTN)(0x1234000000000000ULL+Attempt);
    a->Arg1=0xa5;a->Arg2=0xa6;a->Arg3=0xa7;return;
  }
  Attempt=0;a->Arg0=a->Arg1=a->Arg2=a->Arg3=0;
  if(Mode>=2&&Mode<=4){if(Mode==2)a->Arg1=1;if(Mode==3)a->Arg2=1;if(Mode==4)a->Arg3=1;return;}
  if(Mode==9&&cmd==0x2113){a->Arg0=3;return;}
  UINTN n=0;
  if(cmd==0x310f){
    UINT8 begin[]={0xa2,0x16,0,0x18,0x22,1};memcpy(Page+bo+8,begin,sizeof(begin));n=sizeof(begin);
  }else if(cmd==0x3111){
    UINT8 update[]={0xa3,0x16,0,0x18,0x24,0x58,0x20};memcpy(Page+bo+8,update,sizeof(update));
    memset(Page+bo+8+7,0x5a,32);Page[bo+8+39]=0x18;Page[bo+8+40]=0x25;Page[bo+8+41]=0x18;Page[bo+8+42]=48;n=43;
  }else if(cmd==0x3112){UINT8 finish[]={0xa2,0x16,0,0x18,0x24,0x40};memcpy(Page+bo+8,finish,sizeof(finish));n=sizeof(finish);}
  else assert(cmd==0x2113);
  Put(Page+bo+4,(UINT32)n);
  if((Mode==6&&cmd==0x310f)||((Mode==7||Mode==9||Mode==10)&&cmd==0x3111)||(Mode==8&&cmd==0x3112)||(Mode==10&&cmd==0x2113)){
    memset(Page+bo,0,U32(Page+56));Put(Page+bo,0xffffffdfU);
  }
  if(Mode==5)Page[FKM_MESSAGE_BYTES+8]=1;
  if(Mode==12)Page[12]^=1;
}
static EFI_STATUS Read(void *c,FKR_FILE f,void *p,UINTN cap,UINTN *n){
  (void)c;*n=f==FkrVersionFile?1:f==FkrSecdiscardableFile?16384:f==FkrKeymasterBlobFile?208:60;
  assert(*n<=cap);memset(p,0x45,*n);if(f==FkrVersionFile)*(UINT8*)p='1';return EFI_SUCCESS;
}
static void Setup(void){
  Page=mmap((void*)0x20000000,0x82000,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0);
  assert(Page!=MAP_FAILED&&((UINTN)Page&4095)==0&&(UINTN)Page+0x82000<=0x100000000ULL);
  Calls=Clean=Inv=Attempt=0;
}
static void Run(int mode){
  FSE_CONTEXT c={0};FKM_CONTEXT *b=calloc(1,sizeof(*b));FKR_WORK *w=calloc(1,sizeof(*w));FKR_OPS ops;EFI_STATUS s;
  Mode=mode;Interrupts=mode==1?9:mode==11?3:0;Setup();assert(b&&w);
  assert(FseInitialize(&c,Page,(UINTN)Page,0x82000,0x5c,4,FALSE)==EFI_NOT_READY&&!Calls&&!Clean);
  assert(FseInitialize(&c,Page,(UINTN)Page,0x82000,0x5c,4,TRUE)==EFI_SUCCESS);
  assert(FkmInitialize(b,4,Page,FKM_SHARED_BYTES,FseExchange,&c,TRUE,&ops)==EFI_SUCCESS);
  assert(FkrPrepare(w,Read,NULL,TRUE,NULL,0)==EFI_SUCCESS);
  s=FkrRecoverExisting(w,&ops);
  if(mode==0||mode==11){
    assert(s==EFI_SUCCESS&&w->State==FkrRecovered&&b->Handle==0&&c.State==FseBound);
    assert(Calls==(mode==11?6U:3U)&&Clean==3&&Inv==3&&c.Resumes==Interrupts);
    assert(FsePermitCleanup(&c,b)==EFI_SUCCESS&&Clean==4&&c.State==FseClosed&&!b->Ready);
    FKM_RETURN result;UINTN calls=Calls;
    assert(EFI_ERROR(FseExchange(&c,Page,FKM_MESSAGE_BYTES,4096,&result))&&Calls==calls);
    assert(FsePermitCleanup(&c,b)==EFI_ACCESS_DENIED);
  }else if(mode==6||mode==7||mode==8){
    assert(EFI_ERROR(s)&&w->State==FkrFailed&&c.State==FseBound&&!b->Handle);
    assert(FsePermitCleanup(&c,b)==EFI_SUCCESS&&c.State==FseClosed);
  }else{
    assert(EFI_ERROR(s)&&w->State==FkrQuarantined&&b->Quarantined);
    UINT8 *copy=malloc(FKM_SHARED_BYTES);assert(copy);memcpy(copy,Page,FKM_SHARED_BYTES);
    UINTN clean=Clean,calls=Calls;assert(FsePermitCleanup(&c,b)==EFI_ACCESS_DENIED&&Clean==clean&&Calls==calls);
    assert(!memcmp(copy,Page,FKM_SHARED_BYTES));assert(FkrReset(w)==EFI_ACCESS_DENIED);free(copy);
    if(mode==1){assert(Calls==9&&c.Resumes==8&&Clean==1&&!Inv&&c.State==FseQuarantined);}
  }
  // Host teardown of a fake monitor only; never a production quarantine exit.
  munmap(Page,0x82000);free(b);free(w);Cases++;
}
static void Gates(void){
  FSE_CONTEXT c={0};FKM_RETURN r;Mode=0;Interrupts=0;Setup();
  assert(FseInitialize(&c,Page,(UINTN)Page+4096,0x82000,1,4,TRUE)==EFI_INVALID_PARAMETER);Cases++;
  assert(FseInitialize(&c,Page,0x100000000ULL,0x82000,1,4,TRUE)==EFI_INVALID_PARAMETER);Cases++;
  assert(FseInitialize(&c,Page,(UINTN)Page,FKM_SHARED_BYTES-1,1,4,TRUE)==EFI_INVALID_PARAMETER);Cases++;
  assert(FseInitialize(&c,Page,(UINTN)Page,0x82000,0,4,TRUE)==EFI_INVALID_PARAMETER);Cases++;
  assert(FseInitialize(&c,Page,(UINTN)Page,0x82000,1,0x80000004U,TRUE)==EFI_INVALID_PARAMETER);Cases++;
  assert(FseInitialize(&c,Page,(UINTN)Page,0x82000,1,4,TRUE)==EFI_SUCCESS);
  FKM_CONTEXT *b=calloc(1,sizeof(*b));assert(b);b->Ready=TRUE;b->App=4;b->Shared=Page;b->SharedBytes=FKM_SHARED_BYTES;
  b->Handle=1;assert(FsePermitCleanup(&c,b)==EFI_ACCESS_DENIED&&!Clean);Cases++;
  b->Handle=0;b->RequestBytes=1;assert(FsePermitCleanup(&c,b)==EFI_ACCESS_DENIED&&!Clean);Cases++;
  b->RequestBytes=0;b->Request[0]=1;assert(FsePermitCleanup(&c,b)==EFI_ACCESS_DENIED&&!Clean);Cases++;
  b->Request[0]=0;Page[100]=1;assert(FsePermitCleanup(&c,b)==EFI_ACCESS_DENIED&&!Clean);Cases++;Page[100]=0;free(b);
  Put(Page,4);Put(Page+8,0x424);Put(Page+12,96);Put(Page+16,4);Put(Page+96,0x2116);
  assert(EFI_ERROR(FseExchange(&c,Page,FKM_MESSAGE_BYTES,4096,&r))&&!Calls&&!Clean&&c.State==FseQuarantined);Cases++;
  assert(FseInitialize(&c,Page,(UINTN)Page,0x82000,1,4,TRUE)==EFI_ACCESS_DENIED);Cases++;
  FSE_CONTEXT second={0};assert(FseInitialize(&second,Page,(UINTN)Page,0x82000,1,4,TRUE)==EFI_SUCCESS);
  second.Calls=FSE_CALL_LIMIT;Put(Page+96,0x310f);
  assert(EFI_ERROR(FseExchange(&second,Page,FKM_MESSAGE_BYTES,4096,&r))&&!Calls&&!Clean&&second.State==FseQuarantined);Cases++;
  munmap(Page,0x82000);
}
int main(void){
#if FUXI_M3_SECRET_EXCHANGE
  for(int mode=0;mode<=12;mode++)Run(mode);
  Gates();printf("PASS %u secret exchange/core vectors; monitor simulated, no live SMC/GCM\n",Cases);
#else
  (void)Run;(void)Gates;FSE_CONTEXT c={0};FKM_CONTEXT b={0};FKM_RETURN r;
  assert(FseInitialize(&c,NULL,0,0,0,0,TRUE)==EFI_UNSUPPORTED);
  assert(FseExchange(&c,NULL,0,0,&r)==EFI_UNSUPPORTED&&!Calls&&!Clean&&!Inv);
  assert(FsePermitCleanup(&c,&b)==EFI_UNSUPPORTED);puts("PASS default-off: no SMC/cache calls");
#endif
  return 0;
}
