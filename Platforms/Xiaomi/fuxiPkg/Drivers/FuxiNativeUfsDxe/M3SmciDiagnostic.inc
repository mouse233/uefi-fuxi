// SPDX-License-Identifier: BSD-2-Clause-Patent
// C2: one root register with null credentials, then release the returned object.
// No app-loader, KeyMint, storage key, callback execution or retry.
#if FUXI_M3_SMCI_ROOT && !FUXI_M3_SMC_CONTEXT
STATIC EFI_STATUS mSmciStatus = EFI_NOT_READY;
STATIC UINT32 SmciU32(CONST UINT8 *P) {
  return P[0] | ((UINT32)P[1]<<8) | ((UINT32)P[2]<<16) | ((UINT32)P[3]<<24);
}
STATIC VOID SmciPut32(UINT8 *P, UINT32 Value) {
  UINTN I; for (I=0; I<4; ++I) P[I]=(UINT8)(Value>>(I*8));
}
STATIC BOOLEAN SmciZero(CONST UINT8 *P, UINTN N) {
  UINTN I; for (I=0; I<N; ++I) if (P[I]) return FALSE; return TRUE;
}
STATIC EFI_STATUS SmciInvoke(UINT64 Raw, UINT8 *Page, UINT32 Object,
                              BOOLEAN Register, UINT32 *Returned) {
  UINT64 Regs[8]; ARM_SMC_ARGS Out;
  UINTN I;
  UINT32 Op=Register ? 5 : 0xffffU, Counts=Register ? 0x1100 : 0;
  ZeroMem(Page, 8192);
  SmciPut32(Page, Object); SmciPut32(Page+4, Op); SmciPut32(Page+8, Counts);
  // Two 4096-byte buffers in one registered 8192-byte contiguous range.
  // qcom-scm.ko: svc=6, cmd=0 or 2, owner=0x32, arginfo=0x224, call type=2.
  // __scm_smc_call: bit31=(type==1), bit30=SMC64, owner in [29:24].
  ZeroMem(Regs, sizeof(Regs));
  Regs[0]=FUXI_M3_SMCI_OBJECT ? 0x72000602ULL : 0x72000600ULL; Regs[1]=0x224;
  Regs[2]=Raw; Regs[3]=4096; Regs[4]=Raw+4096; Regs[5]=4096;
  FnuCacheCiv(&mOps, Page, 8192);
  FnuLog(L"FUXIM3 SMCI %a begin x0=%lx x1=%lx in=%lx out=%lx handle=%x op=%x counts=%x",
         Register ? "register" : "release", Regs[0], Regs[1], Regs[2], Regs[4], Object, Op, Counts);
  FnuSmc64(Regs, &Out);
  FnuCacheInv(&mOps, Page, 8192);
  FnuLog(L"FUXIM3 SMCI %a return a0=%lx a1=%lx a2=%lx a3=%lx",
         Register ? "register" : "release", (UINT64)Out.Arg0, (UINT64)Out.Arg1,
         (UINT64)Out.Arg2, (UINT64)Out.Arg3);
  FnuLog(L"FUXIM3 SMCI %a buffers hdr=%08x/%08x/%08x oi=%08x/%08x oo=%08x/%08x out=%08x/%08x/%08x/%08x",
         Register ? "register" : "release", SmciU32(Page), SmciU32(Page+4), SmciU32(Page+8),
         SmciU32(Page+12), SmciU32(Page+16), SmciU32(Page+20), SmciU32(Page+24),
         SmciU32(Page+4096), SmciU32(Page+4100), SmciU32(Page+4104), SmciU32(Page+4108));
  // Deliberately accept only the all-zero terminal/no-callback tuple. Unknown
  // SMC interruption, response type, object result or piggyback retains memory.
  if (Out.Arg0 || Out.Arg1 || Out.Arg2 || Out.Arg3) return EFI_NOT_READY;
  if (SmciU32(Page)!=Object || SmciU32(Page+4)!=Op || SmciU32(Page+8)!=Counts ||
      !SmciZero(Page+4096,4096)) return EFI_COMPROMISED_DATA;
  if (Register) {
    UINT32 Handle=SmciU32(Page+20);
    if (Handle<=1 || (Handle&0x80000000U)) return EFI_COMPROMISED_DATA;
    // Only the low word of the single output-object descriptor may change.
    for (I=12; I<4096; ++I)
      if ((I<20 || I>=24) && Page[I]) return EFI_COMPROMISED_DATA;
    *Returned=Handle;
    FnuLog(L"FUXIM3 SMCI remote-object=%x; root register only", Handle);
  } else if (!SmciZero(Page+12,4084)) return EFI_COMPROMISED_DATA;
  return EFI_SUCCESS;
}

STATIC VOID FnuSmciRootProbe(VOID) {
  EFI_PHYSICAL_ADDRESS Raw=SIZE_4GB-1;
  UINT8 *Page;
  UINT64 Regs[8]; ARM_SMC_ARGS Out;
  UINT64 Bridge=0;
  UINT32 Object=0, Ignored=0;
  BOOLEAN Retain=FALSE;
  mSmciStatus=EFI_NOT_READY;
  FNU_STAGE("m3-smci-root");
  FnuLog(L"FUXIM3 SMCI mode=%a; one register/release, no fallback",
         FUXI_M3_SMCI_OBJECT ? "object-cmd2" : "legacy-cmd0");
  if (gBS->AllocatePages(AllocateMaxAddress,EfiBootServicesData,2,&Raw)!=EFI_SUCCESS) {
    mSmciStatus=EFI_OUT_OF_RESOURCES;
    FnuLog(L"FUXIM3 SMCI page allocation failed; no call"); return;
  }
  Page=(UINT8 *)(UINTN)Raw;ZeroMem(Page,8192);FnuCacheCiv(&mOps,Page,8192);
  FnuLog(L"FUXIM3 SMCI page phys=%lx bytes=2000; no keys",(UINT64)Raw);
  mSmciStatus=FdpBuildBridgeEnable(Regs);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  FnuLog(L"FUXIM3 SMCI bridge-enable begin");FnuSmc64(Regs,&Out);
  FnuLog(L"FUXIM3 SMCI bridge-enable return a0=%lx a1=%lx a2=%lx a3=%lx",
         (UINT64)Out.Arg0,(UINT64)Out.Arg1,(UINT64)Out.Arg2,(UINT64)Out.Arg3);
  if (Out.Arg0 || Out.Arg1) { mSmciStatus=EFI_NOT_READY;goto Done; }
#if FUXI_M3_BRIDGE_HLOS
  FnuLog(L"FUXIM3 SMCI bridge-profile=hlos vm-count=1 vmid=3 ns-perm=6 tz-perm=6 hyp-flags=0");
  mSmciStatus=FdpBuildBridgeCreateHlos((UINT64)Raw,8192,Regs);
#else
  mSmciStatus=FdpBuildBridgeCreate((UINT64)Raw,8192,0,0,Regs);
#endif
  if (EFI_ERROR(mSmciStatus)) goto Done;
  Retain=TRUE;
  FnuLog(L"FUXIM3 SMCI bridge-create args x0=%lx x1=%lx p0=%lx p1=%lx p2=%lx p3=%lx",
         Regs[0],Regs[1],Regs[2],Regs[3],Regs[4],Regs[5]);
  FnuLog(L"FUXIM3 SMCI bridge-create begin");FnuSmc64(Regs,&Out);
  FnuLog(L"FUXIM3 SMCI bridge-create return a0=%lx a1=%lx a2=%lx a3=%lx",
         (UINT64)Out.Arg0,(UINT64)Out.Arg1,(UINT64)Out.Arg2,(UINT64)Out.Arg3);
  mSmciStatus=FdpDecodeBridgeCreate(Out.Arg0,Out.Arg1,Out.Arg2,&Bridge);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  mSmciStatus=SmciInvoke((UINT64)Raw,Page,1,TRUE,&Object);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  mSmciStatus=SmciInvoke((UINT64)Raw,Page,Object,FALSE,&Ignored);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  FnuLog(L"FUXIM3 SMCI object-release=Success handle=%x",Object);
  Object=0;
  ZeroMem(Page,8192);FnuCacheCiv(&mOps,Page,8192);
  mSmciStatus=FdpBuildBridgeDelete(Bridge,Regs);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  FnuLog(L"FUXIM3 SMCI bridge-delete begin handle=%lx",Bridge);FnuSmc64(Regs,&Out);
  FnuLog(L"FUXIM3 SMCI bridge-delete return a0=%lx a1=%lx a2=%lx a3=%lx",
         (UINT64)Out.Arg0,(UINT64)Out.Arg1,(UINT64)Out.Arg2,(UINT64)Out.Arg3);
  mSmciStatus=Out.Arg0 ? EFI_NOT_READY : EFI_SUCCESS;
  if (!EFI_ERROR(mSmciStatus)) Retain=FALSE;
Done:
  if (Retain) {
    // No further call, wipe, delete or free: callback/in-flight ownership is
    // unknown. No secret was put in either page. The parked probe will reboot.
    FnuLog(L"FUXIM3 SMCI retained bridge=%lx object=%x; unknown/error state, no retry",Bridge,Object);
  } else {
    ZeroMem(Page,8192);FnuCacheCiv(&mOps,Page,8192);gBS->FreePages(Raw,2);
    FnuLog(L"FUXIM3 SMCI released bytes=2000");
  }
  FnuLog(L"FUXIM3 SMCI result=%r retained=%u; no TA, no key, no decrypt",mSmciStatus,(UINT32)Retain);
}
#endif
