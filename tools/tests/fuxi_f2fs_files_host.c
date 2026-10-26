// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#include "F2fsReadOnly.h"
static FILE *Image;
static EFI_STATUS Read(VOID *Context,UINT64 Lba,UINTN Count,VOID *Buffer) {
  (void)Context; assert(Lba<32768 && Count==1);
  if (getenv("F2R_FAIL_LBA") && Lba==strtoull(getenv("F2R_FAIL_LBA"),NULL,0)) return EFI_ACCESS_DENIED;
  if (fseek(Image,(long)(Lba*4096),SEEK_SET) || fread(Buffer,4096,1,Image)!=1) return EFI_DEVICE_ERROR;
  return EFI_SUCCESS;
}
static EFI_STATUS Visit(VOID *Context,CONST CHAR8 *Name,UINTN Length,UINT32 Inode,UINT8 Type) {
  UINTN *Count=Context; assert(Name && Length && Length<=255 && Inode>=3 && Type<=7); ++*Count;
  return EFI_SUCCESS;
}
int main(int Argc,char **Argv) {
  assert(Argc==9); Image=fopen(Argv[1],"rb"); assert(Image);
  F2R_VOLUME Volume={0}; F2R_FILE File={0},Root={0}; UINT8 Work[F2R_WORK_BYTES];
  FDP_DISK Disk={NULL,Read,4096,32767}; FDP_PARTITION Part={0,32767,TRUE};
  EFI_STATUS Prep=strtoull(Argv[3],NULL,0),Lookup=strtoull(Argv[4],NULL,0),ReadStatus=strtoull(Argv[6],NULL,0);
  EFI_STATUS Status=F2rPrepare(&Disk,&Part,&Volume,Work,sizeof(Work));
  if(Status!=Prep) {fprintf(stderr,"prepare %llx expected %llx\n",(unsigned long long)Status,(unsigned long long)Prep);return 1;}
  if(EFI_ERROR(Status)) {assert(!Volume.Prepared);return 0;}
  Status=F2rLookup(&Volume,Argv[2],&File,Work,sizeof(Work));
  if(Status!=Lookup) {fprintf(stderr,"lookup %llx expected %llx\n",(unsigned long long)Status,(unsigned long long)Lookup);return 1;}
  if(EFI_ERROR(Status)) {assert(!File.Valid);return 0;}
  assert(File.Valid && File.Mode==0x8000);
  FILE *Expected=fopen(Argv[7],"rb");assert(Expected);
  assert(!fseek(Expected,0,SEEK_END));long Length=ftell(Expected);assert(Length>=0 && Length<=16384);rewind(Expected);
  UINT8 Bytes[16384],Want[16384]; memset(Bytes,0xa5,sizeof(Bytes));assert(fread(Want,1,(size_t)Length,Expected)==(size_t)Length);fclose(Expected);
  UINTN Got=999;
  Status=F2rReadFile(&File,strtoull(Argv[5],NULL,0),Bytes,(UINTN)Length,&Got,Work,sizeof(Work));
  if(Status!=ReadStatus) {fprintf(stderr,"read %llx expected %llx\n",(unsigned long long)Status,(unsigned long long)ReadStatus);return 1;}
  if(EFI_ERROR(Status)) {assert(!Got);for(long I=0;I<Length;++I)assert(Bytes[I]==0);}
  else {assert(Got==(UINTN)Length);assert(!memcmp(Bytes,Want,Got));}
  // EOF is success with zero bytes; out-of-file offsets never wrap.
  assert(F2rReadFile(&File,File.Bytes,Bytes,1,&Got,Work,sizeof(Work))==EFI_SUCCESS && !Got);
  assert(F2rReadFile(&File,MAX_UINT64,Bytes,1,&Got,Work,sizeof(Work))==EFI_INVALID_PARAMETER && !Got);
  if(atoi(Argv[8])) {
    assert(F2rLookup(&Volume,"/",&Root,Work,sizeof(Work))==EFI_SUCCESS);
    UINTN Count=0;assert(F2rListDirectory(&Root,Visit,&Count,Work,sizeof(Work))==EFI_SUCCESS && Count==3);
  }
  printf("PASS file path=%s bytes=%ld status=%llx\n",Argv[2],Length,(unsigned long long)Status);
  fclose(Image);return 0;
}
