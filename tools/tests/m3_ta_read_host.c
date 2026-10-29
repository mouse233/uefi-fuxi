#define _POSIX_C_SOURCE 200112L
#include <Uefi.h>
#include "DataReadOnly.h"
#include "UfsSha256.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define FUXI_M3_SMCI_TA_BYTES 0x63058U
static UINT8 *mTaImage;
static UINTN mTaImageBytes, mTaImagePages;
static UINT8 partition[128*4096];
static int calls, fail_on, alloc_fail, frees, last_count;
static void *ZeroMem(void *p, UINTN n){return memset(p,0,n);}
static INTN CompareMem(const void *a,const void *b,UINTN n){return memcmp(a,b,n);}
static UINTN UnicodeSPrint(CHAR16 *out,UINTN bytes,const CHAR16 *fmt,...){(void)fmt;assert(bytes>=3*sizeof(CHAR16));out[0]='x';out[1]='x';out[2]=0;return 2;}
static void FnuLog(const CHAR16 *fmt,...){(void)fmt;}
static EFI_STATUS AllocatePages(int type,int mem,UINTN pages,EFI_PHYSICAL_ADDRESS *raw){
 (void)type;(void)mem;if(alloc_fail)return EFI_OUT_OF_RESOURCES;
 void *p=NULL;assert(pages==100);assert(!posix_memalign(&p,4096,pages*4096));*raw=(UINTN)p;return EFI_SUCCESS;
}
static EFI_STATUS FreePages(EFI_PHYSICAL_ADDRESS raw,UINTN pages){
 UINT8 *p=(UINT8 *)(UINTN)raw;assert(pages==100);
 for(UINTN i=0;i<pages*4096;++i)assert(p[i]==0);
 ++frees;free(p);return EFI_SUCCESS;
}
static struct {EFI_STATUS(*AllocatePages)(int,int,UINTN,EFI_PHYSICAL_ADDRESS *);
 EFI_STATUS(*FreePages)(EFI_PHYSICAL_ADDRESS,UINTN);} Boot={AllocatePages,FreePages},*gBS=&Boot;
EFI_STATUS FdpReadPartition(CONST FDP_DISK *disk, CONST FDP_PARTITION *part, UINT64 offset,UINTN blocks,VOID *buffer){
 (void)disk;(void)part;++calls;last_count=(int)blocks;
 assert(blocks>0 && blocks<=16 && offset+blocks<=100);
 if(calls==fail_on)return EFI_DEVICE_ERROR;
 memcpy(buffer,partition+offset*4096,blocks*4096);return EFI_SUCCESS;
}
#include "ta_load_under_test.inc"
static void reset(void){assert(!mTaImage);mTaImageBytes=mTaImagePages=0;calls=fail_on=alloc_fail=frees=last_count=0;}
int main(int argc,char **argv){
 assert(argc==2);FILE *f=fopen(argv[1],"rb");assert(f);assert(fread(partition,1,sizeof(partition),f)==sizeof(partition));fclose(f);
 FDP_DISK disk={0};FDP_PARTITION part={0,127,TRUE};
 reset();assert(FnuLoadTaImage(&disk,&part)==EFI_SUCCESS);assert(calls==7 && last_count==4 && mTaImageBytes==0x63058 && mTaImagePages==100);
 assert(!memcmp(mTaImage,partition,0x63058));ZeroMem(mTaImage,100*4096);FreePages((EFI_PHYSICAL_ADDRESS)(UINTN)mTaImage,100);mTaImage=NULL;
 reset();partition[13]^=1;assert(FnuLoadTaImage(&disk,&part)==EFI_COMPROMISED_DATA);assert(calls==7 && frees==1 && !mTaImage && !mTaImageBytes);partition[13]^=1;
 for(int n=1;n<=7;++n){reset();fail_on=n;assert(FnuLoadTaImage(&disk,&part)==EFI_DEVICE_ERROR);assert(calls==n && frees==1 && !mTaImage);}
 reset();alloc_fail=1;assert(FnuLoadTaImage(&disk,&part)==EFI_OUT_OF_RESOURCES && !calls && !mTaImage);
 reset();part.Present=FALSE;assert(FnuLoadTaImage(&disk,&part)==EFI_COMPROMISED_DATA && !calls);
 puts("PASS 11 actual TA reader vectors with ASan/UBSan");return 0;
}
