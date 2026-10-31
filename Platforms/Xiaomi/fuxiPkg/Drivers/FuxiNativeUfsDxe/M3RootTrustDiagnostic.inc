// SPDX-License-Identifier: BSD-2-Clause-Patent
// One fixed configure + one ROT observation. No recovery input or begin.
#if FUXI_M3_ROOT_TRUST_QUERY
#include "M3RootTrustPublic.h"
STATIC BOOLEAN mRootTrustConfigureSent,mRootTrustConfigured,mRootTrustQuerySent;
STATIC CONST UINT8 mRootTrustConfigure[]={
  0x16,0x21,0,0,0xa4,0x16,3,
  0x1a,0x30,0,2,0xc1,0x1a,0,2,0x98,0x10,
  0x1a,0x30,0,2,0xc2,0x1a,0x01,0x35,0x28,0x8d,
  0x1a,0x30,0,2,0xce,0x1a,0x01,0x35,0x28,0x8d
};
STATIC CONST UINT8 mRootTrustRequest[]={
  0x1f,0x31,0,0,0xa1,4,0x50,
  'F','U','X','I','-','R','O','T','-','P','R','O','B','E','0','1'
};
STATIC EFI_STATUS SmciRootTrustExchange(UINT64 Raw,UINT8 *Page,UINTN Bytes,UINT32 App,BOOLEAN Configure) {
  CONST UINT8 *Request=Configure?mRootTrustConfigure:mRootTrustRequest;
  UINTN Send=Configure?sizeof(mRootTrustConfigure):sizeof(mRootTrustRequest);
  CONST UINTN Cap=0x9fd8,Bi1=0x88,Bi3=0xa060,Bo0=0xa068,Bo1=0xa090;
  UINT64 Regs[8];ARM_SMC_ARGS Out;UINT8 Header[96];UINTN I,OutReq,OutResp;
  UINT32 Status,Payload,Resumes,Boot=0;
  if(mReady || mPoisoned || !mRootTrustVersionOk ||
     (Configure?mRootTrustConfigureSent:(!mRootTrustConfigured || mRootTrustQuerySent)) ||
     Raw!=(UINT64)(UINTN)Page || (Raw&4095) || Raw<4096 || Bytes!=0x82000 ||
     Raw>0x100000000ULL-Bytes || App<=1 || (App&0x80000000U))return EFI_NOT_READY;
  if(Configure)mRootTrustConfigureSent=TRUE;else mRootTrustQuerySent=TRUE;
  ZeroMem(Page,Bytes);SmciPut32(Page,App);SmciPut32(Page+8,0x424);
  SmciPut32(Page+12,96);SmciPut32(Page+16,(UINT32)Send);
  SmciPut32(Page+20,(UINT32)Bi1);SmciPut32(Page+24,(UINT32)Cap);
  SmciPut32(Page+28,(UINT32)Bi3);SmciPut32(Page+36,(UINT32)Bi3);SmciPut32(Page+40,4);
  SmciPut32(Page+44,(UINT32)Bo0);SmciPut32(Page+48,(UINT32)Send);
  SmciPut32(Page+52,(UINT32)Bo1);SmciPut32(Page+56,(UINT32)Cap);
  SmciPut32(Page+Bi3,1);CopyMem(Page+96,Request,Send);CopyMem(Header,Page,96);
  ZeroMem(Regs,sizeof(Regs));Regs[0]=0x72000602;Regs[1]=0x224;
  Regs[2]=Raw;Regs[3]=0x15000;Regs[4]=Raw+0x15000;Regs[5]=4096;
  FNU_STAGE("m3-root-context");
  if(Configure)FnuLog(L"FUXIM3 ROOTCTX configure app=%x os=170000 os-patch=20261005 vendor-patch=20261005",App);
  else FnuLog(L"FUXIM3 ROOTCTX query once app=%x command=311f; TA may initialize private MAC cache",App);
  FnuCacheCiv(&mOps,Page,Bytes);Resumes=SmciCallWithResume(Regs,&Out);
  FnuLog(L"FUXIM3 ROOTCTX smc configure=%u a0=%lx a1=%lx a2=%lx a3=%lx resumes=%u",
         (UINT32)Configure,(UINT64)Out.Arg0,(UINT64)Out.Arg1,(UINT64)Out.Arg2,(UINT64)Out.Arg3,Resumes);
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
    else if(I>=96 && I<96+Send)Expected=Request[I-96];
    else if(I==Bi3)Expected=1;
    if(Page[I]!=Expected)return EFI_NOT_READY;
  }
  Status=SmciU32(Page+Bo1);Payload=SmciU32(Page+Bo1+4);
  FnuLog(L"FUXIM3 ROOTCTX response configure=%u status=%08x payload=%u wire=%u",
         (UINT32)Configure,Status,Payload,(UINT32)OutResp);
  // All errors/unknown ownership retain the unmodified registered allocation.
  if(Status)return EFI_NOT_READY;
  if(Configure) {
    if(OutResp!=Cap || Payload!=Cap-8 || !SmciZero(Page+Bo1+8,Cap-8))return EFI_NOT_READY;
    mRootTrustConfigured=TRUE;
  } else {
    if(Payload>256 || Payload>OutResp-8 ||
       (OutResp!=Cap && OutResp!=Payload+8) ||
       !SmciZero(Page+Bo1+8+Payload,OutResp-8-Payload) ||
       !FnuReadRootTrustBoot(Page+Bo1+8,Payload,&Boot))return EFI_NOT_READY;
  }
  ZeroMem(Page,Bytes);FnuCacheCiv(&mOps,Page,Bytes);
  if(Configure)FnuLog(L"FUXIM3 ROOTCTX configure Success; continue one query");
  else FnuLog(L"FUXIM3 ROOTCTX boot-patch=%u; structural observation only, MAC unverified",Boot);
  return EFI_SUCCESS;
}
#endif
