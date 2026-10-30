// SPDX-License-Identifier: BSD-2-Clause-Patent
// Synthetic filesystem and monitor only. No actual recovery keys or GCM.
static int Scenario,SecretCalls,SecretUnknown,PoolCalls,PoolLive;
static UINT8 *SecretSnapshot;
static BOOLEAN mPoisoned,mReady;
static struct { void *p;UINTN n; } Pools[8];
static void *AllocateZeroPool(UINTN n){
 ++PoolCalls;if(Scenario==11&&PoolCalls==3)return NULL;
 void *p=calloc(1,n);assert(p);Pools[PoolLive].p=p;Pools[PoolLive].n=n;PoolLive++;return p;
}
static void FreePool(void *p){
 for(int i=0;i<PoolLive;i++)if(Pools[i].p==p){
  for(UINTN j=0;j<Pools[i].n;j++)assert(!((UINT8*)p)[j]);
  free(p);Pools[i]=Pools[--PoolLive];return;
 }assert(0);
}
EFI_STATUS F2rPrepare(CONST FDP_DISK *d,CONST FDP_PARTITION *p,F2R_VOLUME *v,VOID *w,UINTN n){
 (void)d;(void)p;(void)v;(void)w;assert(n==F2R_WORK_BYTES);return EFI_SUCCESS;
}
EFI_STATUS FkrReadF2fsFile(VOID *c,FKR_FILE f,VOID *out,UINTN cap,UINTN *n){
 FKR_F2FS_CONTEXT *r=c;assert(r->Volume&&r->Work&&r->WorkBytes==F2R_WORK_BYTES);
 if(Scenario==12&&f==FkrEncryptedKeyFile)return EFI_DEVICE_ERROR;
 *n=f==FkrVersionFile?1:f==FkrSecdiscardableFile?16384:f==FkrKeymasterBlobFile?208:276;
 assert(cap>=*n);memset(out,0x65,*n);if(f==FkrVersionFile)*(UINT8*)out='1';return EFI_SUCCESS;
}
VOID *EFIAPI WriteBackInvalidateDataCacheRange(VOID *p,UINTN n){assert(p==Page&&n==FKM_SHARED_BYTES);return p;}
VOID *EFIAPI InvalidateDataCacheRange(VOID *p,UINTN n){assert(p==Page&&n==FKM_SHARED_BYTES);return p;}
static int SecretMonitor(ARM_SMC_ARGS *a){
 UINT32 cmd=*(UINT32*)(Page+96),bo=*(UINT32*)(Page+52);
 if(cmd!=0x310f&&cmd!=0x3111&&cmd!=0x3112&&cmd!=0x2113)return 0;
 assert(!SecretUnknown);++SecretCalls;
 assert(a->Arg0==0x72000602&&a->Arg1==0x224&&a->Arg2==(UINTN)Page&&a->Arg3==FKM_MESSAGE_BYTES&&a->Arg4==(UINTN)(Page+FKM_MESSAGE_BYTES)&&a->Arg5==4096);
 a->Arg0=a->Arg1=a->Arg2=a->Arg3=0;
 if((Scenario==4&&cmd==0x310f)||(Scenario==5&&cmd==0x3111)||(Scenario==8&&cmd==0x2113))a->Arg0=3;
 else if((Scenario==1&&cmd==0x310f)||((Scenario==2||Scenario==7||Scenario==8)&&cmd==0x3111)||(Scenario==3&&cmd==0x3112)||(Scenario==7&&cmd==0x2113)){
   Put(Page+bo,0xffffffdfU);Put(Page+bo+4,0);
 }else if(cmd==0x310f){UINT8 b[]={0xa2,0x16,0,0x18,0x22,1};memcpy(Page+bo+8,b,sizeof(b));Put(Page+bo+4,sizeof(b));}
 else if(cmd==0x3111){
   UINT8 b[]={0xa3,0x16,0,0x18,0x24,0x58,0xf8};memcpy(Page+bo+8,b,sizeof(b));memset(Page+bo+15,0x5a,248);
   UINT8 tail[]={0x18,0x25,0x19,1,8};memcpy(Page+bo+15+248,tail,sizeof(tail));Put(Page+bo+4,7+248+sizeof(tail));
 }else if(cmd==0x3112){UINT8 b[]={0xa2,0x16,0,0x18,0x24,0x40};memcpy(Page+bo+8,b,sizeof(b));Put(Page+bo+4,sizeof(b));}
 else Put(Page+bo+4,0);
 if(Scenario==6&&cmd==0x3112)Put(Page+bo+4,0xffffffffU);
 if(Scenario==9)Page[FKM_MESSAGE_BYTES+8]=1;
 if(a->Arg0 || (Scenario==6&&cmd==0x3112) || Scenario==9 || (Scenario==7&&cmd==0x2113)){
   SecretUnknown=1;SecretSnapshot=malloc(TEST_BYTES);assert(SecretSnapshot);memcpy(SecretSnapshot,Page,TEST_BYTES);
 }
 return 1;
}
