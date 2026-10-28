// SPDX-License-Identifier: BSD-2-Clause-Patent
// Real F2FS + SHA + production C1 lifecycle; simulated allocation/cache/SMC.
#define _POSIX_C_SOURCE 200112L
#include "F2fsReadOnly.h"
#include "UfsSha256.h"
#include <Library/ArmSmcLib.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define FUXI_M3_BRIDGE_BLOB 1
#define FUXI_M3_SCM_BRIDGE_CALL 1
#define FNU_STAGE(Name) ((void)(Name))
static FILE *Image;
static VOID *Page;
static UINTN PageBytes;
static int Calls, Frees, Prefixes, FailCall, FailAlloc, FailPool, Pools, LivePools;
static int CacheCorrupt, FailRead;
static EFI_STATUS ReadStatus;
static int mOps;
static void *ZeroMem(void *p, UINTN n) { return memset(p, 0, n); }
static void *AllocateZeroPool(UINTN n) {
  if (++Pools == FailPool) return NULL;
  void *p = calloc(1, n); if (p) ++LivePools; return p;
}
static void FreePool(void *p) { assert(p); --LivePools; free(p); }
static void FnuLog(CONST CHAR16 *fmt, ...) {
  char text[320]; UINTN i = 0;
  for (; fmt[i] && i < sizeof(text)-1; ++i) text[i]=(char)fmt[i];
  text[i]=0;
  if (strstr(text, "prefix32=")) ++Prefixes;
  if (strstr(text, "BLOB read=")) {
    va_list a; va_start(a,fmt); ReadStatus=va_arg(a,EFI_STATUS); va_end(a);
  }
}
static int AllZero(const void *p, UINTN n) {
  const UINT8 *b=p; for (UINTN i=0;i<n;++i) if(b[i]) return 0; return 1;
}
static void FnuCacheCiv(void *ops, void *p, UINTN n) {
  (void)ops;
  if (CacheCorrupt && !AllZero(p,n)) { ((UINT8 *)p)[0]^=1; CacheCorrupt=0; }
}
static EFI_STATUS AllocatePages(int type,int memory,UINTN pages,EFI_PHYSICAL_ADDRESS *raw) {
  (void)type;(void)memory;
  assert(!Page && pages==2);
  if(FailAlloc) return EFI_OUT_OF_RESOURCES;
  PageBytes=EFI_PAGES_TO_SIZE(pages);
  assert(posix_memalign(&Page,4096,PageBytes)==0);
  *raw=(UINTN)Page; return EFI_SUCCESS;
}
static EFI_STATUS FreePages(EFI_PHYSICAL_ADDRESS raw,UINTN pages) {
  assert((UINTN)Page==raw && pages==2 && AllZero(Page,PageBytes));
  ++Frees;free(Page);Page=NULL;return EFI_SUCCESS;
}
static struct {
  EFI_STATUS (*AllocatePages)(int,int,UINTN,EFI_PHYSICAL_ADDRESS *);
  EFI_STATUS (*FreePages)(EFI_PHYSICAL_ADDRESS,UINTN);
} BootServices={AllocatePages,FreePages}, *gBS=&BootServices;
VOID EFIAPI ArmCallSmc(ARM_SMC_ARGS *a) {
  ++Calls;
  if(Calls==1) assert(a->Arg0==0x42000c1c && a->Arg1==0);
  else if(Calls==2) {
    assert(a->Arg0==0x42000c1e && a->Arg1==4);
    assert(a->Arg2==(UINTN)Page && a->Arg3==((UINTN)Page|6) && a->Arg4==8192);
    assert(AllZero(Page,PageBytes));
  } else {
    assert(Calls==3 && a->Arg0==0x42000c1d && a->Arg2==0x5c);
    assert(AllZero(Page,PageBytes));
  }
  a->Arg0=Calls==FailCall?1:0;
  a->Arg1=0;
  a->Arg2=Calls==2?0x5c:0; a->Arg3=0;
}
#include "M3BridgeBlob.inc"
#include "M3BridgeDiagnostic.inc"
static EFI_STATUS Read(VOID *ctx,UINT64 lba,UINTN count,VOID *buffer) {
  (void)ctx; assert(count==1 && lba<32768);
  if(FailRead) return EFI_DEVICE_ERROR;
  if(fseek(Image,(long)(lba*4096),SEEK_SET) || fread(buffer,4096,1,Image)!=1)
    return EFI_DEVICE_ERROR;
  return EFI_SUCCESS;
}
static void Reset(void) {
  assert(!Page && LivePools==0);
  Calls=Frees=Prefixes=FailCall=FailAlloc=FailPool=Pools=CacheCorrupt=FailRead=0;
  ReadStatus=EFI_NOT_READY;
}
int main(int argc,char **argv) {
  FDP_DISK disk={NULL,Read,4096,32767};
  FDP_PARTITION part={0,32767,TRUE};
  UINT8 work[F2R_WORK_BYTES], expected[32], data[M3B_BLOB_BYTES];
  FNU_SHA256_CTX hash;
  assert(argc==3);Image=fopen(argv[1],"rb");assert(Image);
  (void)mM3BlobExpectedSha;
  for(UINTN i=0;i<sizeof(data);++i) data[i]=(UINT8)((i*7+0xa5)&255);
  FnuSha256Init(&hash);FnuSha256Update(&hash,data,sizeof(data));FnuSha256Final(&hash,expected);
  if(strcmp(argv[2],"valid")) {
    Reset();FnuBridgeCallProbe(&disk,&part,work,expected);
    assert(Calls==3 && Frees==1 && Prefixes==0 && EFI_ERROR(ReadStatus));
    assert(LivePools==0);fclose(Image);puts("PASS malformed fixture stopped and deleted");return 0;
  }
  Reset();FnuBridgeCallProbe(&disk,&part,work,expected);
  assert(Calls==3 && Frees==1 && Prefixes==1 && ReadStatus==EFI_SUCCESS);
  Reset();FailCall=3;FnuBridgeCallProbe(&disk,&part,work,expected);
  assert(Calls==3 && Frees==0 && Page && AllZero(Page,PageBytes));
  free(Page);Page=NULL; // Host-only teardown of retained allocation.
  Reset();FailCall=1;FnuBridgeCallProbe(&disk,&part,work,expected);
  assert(Calls==1 && Frees==1 && Prefixes==0);
  Reset();FailCall=2;FnuBridgeCallProbe(&disk,&part,work,expected);
  assert(Calls==2 && Frees==0 && Prefixes==0 && Page && AllZero(Page,PageBytes));
  free(Page);Page=NULL; // Host-only teardown of unknown create ownership.
  Reset();FailAlloc=1;FnuBridgeCallProbe(&disk,&part,work,expected);
  assert(Calls==0 && Frees==0);
  for(int i=1;i<=2;++i) {
    Reset();FailPool=i;FnuBridgeCallProbe(&disk,&part,work,expected);
    assert(Calls==3 && Frees==1 && Prefixes==0 && ReadStatus==EFI_OUT_OF_RESOURCES && LivePools==0);
  }
  Reset();expected[0]^=1;FnuBridgeCallProbe(&disk,&part,work,expected);expected[0]^=1;
  assert(Calls==3 && Frees==1 && Prefixes==0 && ReadStatus==EFI_CRC_ERROR);
  Reset();CacheCorrupt=1;FnuBridgeCallProbe(&disk,&part,work,expected);
  assert(Calls==3 && Frees==1 && Prefixes==0 && ReadStatus==EFI_CRC_ERROR);
  Reset();FailRead=1;FnuBridgeCallProbe(&disk,&part,work,expected);
  assert(Calls==3 && Frees==1 && Prefixes==0 && EFI_ERROR(ReadStatus));
  assert(LivePools==0);
  fclose(Image);puts("PASS C1 production F2FS/SHA and bridge lifetime failure paths");return 0;
}
