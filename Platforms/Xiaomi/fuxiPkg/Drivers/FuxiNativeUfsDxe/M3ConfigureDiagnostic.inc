// SPDX-License-Identifier: BSD-2-Clause-Patent
// One PUBLIC configure before any secret request. Fixed audited TA/QTI subset.
#if FUXI_M3_CONFIGURE_RECOVERY
#ifndef FUXI_M3_CONFIGURE_PATCH
#define FUXI_M3_CONFIGURE_PATCH 20261005
#endif
#if FUXI_M3_CONFIGURE_PATCH != 20261005 && FUXI_M3_CONFIGURE_PATCH != 20991231
#error Unsupported public configure profile
#endif
#define FKM_PATCH_BYTES 0x1a, ((FUXI_M3_CONFIGURE_PATCH >> 24) & 255), ((FUXI_M3_CONFIGURE_PATCH >> 16) & 255), ((FUXI_M3_CONFIGURE_PATCH >> 8) & 255), (FUXI_M3_CONFIGURE_PATCH & 255)
STATIC CONST UINT8 mConfigureRequest[] = {
  0x16,0x21,0,0,0xa4,0x16,3,
  0x1a,0x30,0,2,0xc1,0x1a,0,2,0x98,0x10,
  0x1a,0x30,0,2,0xc2,FKM_PATCH_BYTES,
  0x1a,0x30,0,2,0xce,FKM_PATCH_BYTES
};
#undef FKM_PATCH_BYTES
STATIC EFI_STATUS SmciConfigureRecovery(UINT64 Raw,UINT8 *Page,UINTN Bytes,UINT32 App) {
  UINT64 Regs[8]; ARM_SMC_ARGS Out; UINT8 Header[96];UINTN I;
  CONST UINTN Send=sizeof(mConfigureRequest),Cap=0x9fd8,Bi1=0x88,Bi3=0xa060,Bo0=0xa068,Bo1=0xa090;
  UINTN OutReq,OutResp;UINT32 Status,Payload,Resumes;
  if(mReady || mPoisoned || !mRecoveryVersionOk || mRecoveryWork==NULL ||
     mRecoveryWork->State!=FkrPrepared || Raw!=(UINT64)(UINTN)Page || (Raw&4095) ||
     Raw<4096 || Bytes!=0x82000 || Raw>0x100000000ULL-Bytes || App<=1 ||
     (App&0x80000000U))return EFI_NOT_READY;
  // No registered page has contained secret requests yet. This is never a
  // recovery retry or a way to reuse the previous boot's retained session.
  ZeroMem(Page,Bytes);SmciPut32(Page,App);SmciPut32(Page+8,0x424);
  SmciPut32(Page+12,96);SmciPut32(Page+16,(UINT32)Send);
  SmciPut32(Page+20,(UINT32)Bi1);SmciPut32(Page+24,(UINT32)Cap);
  SmciPut32(Page+28,(UINT32)Bi3);SmciPut32(Page+36,(UINT32)Bi3);SmciPut32(Page+40,4);
  SmciPut32(Page+44,(UINT32)Bo0);SmciPut32(Page+48,(UINT32)Send);
  SmciPut32(Page+52,(UINT32)Bo1);SmciPut32(Page+56,(UINT32)Cap);
  SmciPut32(Page+Bi3,1);CopyMem(Page+96,mConfigureRequest,Send);CopyMem(Header,Page,96);
  ZeroMem(Regs,sizeof(Regs));Regs[0]=0x72000602;Regs[1]=0x224;
  Regs[2]=Raw;Regs[3]=0x15000;Regs[4]=Raw+0x15000;Regs[5]=4096;
  FNU_STAGE("m3-configure-recovery");
  FnuLog(L"FUXIM3 CONFIGURE begin once: os=170000 os-patch=%u vendor-patch=%u evidence=%08x",(UINT32)FUXI_M3_CONFIGURE_PATCH,(UINT32)FUXI_M3_CONFIGURE_PATCH,(UINT32)FUXI_M3_CONFIGURE_TAG);
  FnuCacheCiv(&mOps,Page,Bytes);Resumes=SmciCallWithResume(Regs,&Out);
  FnuLog(L"FUXIM3 CONFIGURE return a0=%lx a1=%lx a2=%lx a3=%lx resumes=%u",
         (UINT64)Out.Arg0,(UINT64)Out.Arg1,(UINT64)Out.Arg2,(UINT64)Out.Arg3,Resumes);
  if(Out.Arg0 || Out.Arg1 || Out.Arg2 || Out.Arg3)return EFI_NOT_READY;
  FnuCacheInv(&mOps,Page,Bytes);
  if(!((SmciU32(Page+0x15000)==0 && SmciU32(Page+0x15004)==0) ||
       (SmciU32(Page+0x15000)==0x10002 &&
        (SmciU32(Page+0x15004)==0xfffd || SmciU32(Page+0x15004)==0xffff))) ||
     !SmciZero(Page+0x15008,4088))return EFI_NOT_READY;
  OutReq=SmciU32(Page+48);OutResp=SmciU32(Page+56);
  if(OutReq>Send || OutResp<8 || OutResp>Cap)return EFI_NOT_READY;
  for(I=0;I<0x15000;++I) {
    UINT8 Expected=0;
    if((I>=48 && I<52) || (I>=56 && I<60) ||
       (I>=Bo0 && I<Bo0+OutReq) || (I>=Bo1 && I<Bo1+OutResp))continue;
    if(I<96)Expected=Header[I];
    else if(I>=96 && I<96+Send)Expected=mConfigureRequest[I-96];
    else if(I==Bi3)Expected=1;
    if(Page[I]!=Expected)return EFI_NOT_READY;
  }
  Status=SmciU32(Page+Bo1);Payload=SmciU32(Page+Bo1+4);
  FnuLog(L"FUXIM3 CONFIGURE header status=%08x payload=%u wire=%u; public fields only",Status,Payload,(UINT32)OutResp);
  // Fixed b7b4 wrapper has no output writer: the generic dispatcher leaves
  // capacity-8 as its payload length, with zero output. No other success shape
  // or nonzero TA status authorizes a key call or remote cleanup.
  if(Status || OutResp!=Cap || Payload!=Cap-8 || !SmciZero(Page+Bo1+8,Cap-8))return EFI_NOT_READY;
  ZeroMem(Page,Bytes);FnuCacheCiv(&mOps,Page,Bytes);
  FnuLog(L"FUXIM3 CONFIGURE Success; continue existing-key recovery");
  return EFI_SUCCESS;
}
#endif
