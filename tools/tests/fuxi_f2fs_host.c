// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#include "F2fsReadOnly.h"
static FILE *Image;
static UINTN Reads;
static EFI_STATUS Read(VOID *Context,UINT64 Lba,UINTN Count,VOID *Buffer) {
  (void)Context; ++Reads;
  assert (Lba<32768 && Count==1);
  if (getenv("F2R_FAIL_LBA") && Lba==strtoull(getenv("F2R_FAIL_LBA"),NULL,0)) return EFI_ACCESS_DENIED;
  if (fseek(Image,(long)(Lba*4096),SEEK_SET) || fread(Buffer,4096,1,Image)!=1) return EFI_DEVICE_ERROR;
  return EFI_SUCCESS;
}
int main(int Argc,char **Argv) {
  assert(Argc==5);
  Image=fopen(Argv[1],"rb");assert(Image);
  FDP_DISK Disk={NULL,Read,4096,32767};
  FDP_PARTITION Part={0,32767,TRUE};
  F2R_VOLUME Volume={0}; UINT8 Work[F2R_WORK_BYTES],Dentry[4096]={0};
  EFI_STATUS Expected=(EFI_STATUS)strtoull(Argv[2],NULL,0);
  EFI_STATUS Status=F2rPrepare(&Disk,&Part,&Volume,Work,sizeof(Work));
  if(Status!=Expected) { fprintf(stderr,"actual=%llx expected=%llx\n",(unsigned long long)Status,(unsigned long long)Expected); return 1; }
  if(!EFI_ERROR(Status)) {
    assert(Volume.SelectedPack==(UINT32)strtoul(Argv[3],NULL,0));
    UINT64 Block; UINTN Offset;
    assert(F2rPlanNatRead(&Volume,3,&Block,&Offset)==EFI_SUCCESS);
    assert(Block==(UINT64)strtoull(Argv[4],NULL,0) && Offset==27);
    assert(F2rPlanNatRead(&Volume,MAX_UINT32,&Block,&Offset)==EFI_VOLUME_CORRUPTED);
    assert(F2rPrepare(&Disk,&Part,&Volume,Work,1)==EFI_INVALID_PARAMETER && !Volume.Prepared);
  } else assert(!Volume.Prepared);
  // The fixed disk-format dentry layout is encoded independently here.
  UINT32 Inode=0;UINT8 Type=0;
  Dentry[0]=1; Dentry[34]=9; Dentry[38]=4; Dentry[40]=1;
  memcpy(Dentry+2384,"test",4);
  assert(F2rFindDentry(Dentry,"test",4,&Inode,&Type)==EFI_SUCCESS && Inode==9 && Type==1);
  assert(F2rFindDentry(Dentry,"none",4,&Inode,&Type)==EFI_NOT_FOUND);
  Dentry[38]=255; // continuation slots are not marked allocated.
  assert(F2rFindDentry(Dentry,"test",4,&Inode,&Type)==EFI_VOLUME_CORRUPTED);
  assert(F2rFindDentry(Dentry,"a/b",3,&Inode,&Type)==EFI_INVALID_PARAMETER);
  fclose(Image);
  printf("PASS F2FS bootstrap status=%llx reads=%zu and dentry corruption checks\n",(unsigned long long)Status,(size_t)Reads);
  return 0;
}
