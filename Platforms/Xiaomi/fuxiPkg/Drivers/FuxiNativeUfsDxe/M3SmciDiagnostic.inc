// SPDX-License-Identifier: BSD-2-Clause-Patent
// C2 root-only, or explicit C2/C3 batch: root -> open UID122 loader -> release
// loader -> release environment -> delete bridge. No TA, key, callback or retry.
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
                              UINT32 Kind, UINT32 *Returned) {
  UINT64 Regs[8]; ARM_SMC_ARGS Out;
  UINTN I;
  BOOLEAN Register=(Kind==1), Open=FALSE;
  CONST CHAR8 *Stage=Register ? "register" : "release";
  UINT32 Op=Register ? 5 : 0xffffU, Counts=Register ? 0x1100 : 0;
#if FUXI_M3_SMCI_LOADER
  Open=(Kind==2);
  if (Open) { Op=0;Counts=0x1001;Stage="loader-open"; }
#endif
  ZeroMem(Page, 8192);
  SmciPut32(Page, Object); SmciPut32(Page+4, Op); SmciPut32(Page+8, Counts);
#if FUXI_M3_SMCI_LOADER
  if (Open) {
    // BI1/OO1: 12-byte header + two 8-byte descriptors = 28, align8 -> 32.
    // Fixed IClientEnv_open: uint32 UID122, op0, counts0x1001. No TA name.
    SmciPut32(Page+12,32);SmciPut32(Page+16,4);SmciPut32(Page+32,122);
    FnuLog(L"FUXIM3 SMCI loader-open BI offset=20 size=4 uid=7A; no TA load");
  }
#endif
  // Two 4096-byte buffers in one registered 8192-byte contiguous range.
  // qcom-scm.ko: svc=6, cmd=0 or 2, owner=0x32, arginfo=0x224, call type=2.
  // __scm_smc_call: bit31=(type==1), bit30=SMC64, owner in [29:24].
  ZeroMem(Regs, sizeof(Regs));
  Regs[0]=FUXI_M3_SMCI_OBJECT ? 0x72000602ULL : 0x72000600ULL; Regs[1]=0x224;
  Regs[2]=Raw; Regs[3]=4096; Regs[4]=Raw+4096; Regs[5]=4096;
  FnuCacheCiv(&mOps, Page, 8192);
  FnuLog(L"FUXIM3 SMCI %a begin x0=%lx x1=%lx in=%lx out=%lx handle=%x op=%x counts=%x",
         Stage, Regs[0], Regs[1], Regs[2], Regs[4], Object, Op, Counts);
  FnuSmc64(Regs, &Out);
  FnuCacheInv(&mOps, Page, 8192);
  FnuLog(L"FUXIM3 SMCI %a return a0=%lx a1=%lx a2=%lx a3=%lx",
         Stage, (UINT64)Out.Arg0, (UINT64)Out.Arg1,
         (UINT64)Out.Arg2, (UINT64)Out.Arg3);
  FnuLog(L"FUXIM3 SMCI %a buffers hdr=%08x/%08x/%08x oi=%08x/%08x oo=%08x/%08x out=%08x/%08x/%08x/%08x",
         Stage, SmciU32(Page), SmciU32(Page+4), SmciU32(Page+8),
         SmciU32(Page+12), SmciU32(Page+16), SmciU32(Page+20), SmciU32(Page+24),
         SmciU32(Page+4096), SmciU32(Page+4100), SmciU32(Page+4104), SmciU32(Page+4108));
  // Deliberately accept only the all-zero terminal/no-callback tuple. Unknown
  // SMC interruption, response type, object result or piggyback retains memory.
  if (Out.Arg0 || Out.Arg1 || Out.Arg2 || Out.Arg3) return EFI_NOT_READY;
  if (SmciU32(Page)!=Object || SmciU32(Page+4)!=Op || SmciU32(Page+8)!=Counts ||
      !SmciZero(Page+4096,4096)) return EFI_COMPROMISED_DATA;
  if (Register || Open) {
    UINT32 Handle=SmciU32(Page+20);
    if (Handle<=1 || (Handle&0x80000000U)) return EFI_COMPROMISED_DATA;
    // Only OO low32 may change. The fixed BI descriptor and UID payload must
    // remain intact; reserved words, padding, tail and callback out stay zero.
    if (Open && (SmciU32(Page+12)!=32 || SmciU32(Page+16)!=4 ||
                 SmciU32(Page+32)!=122)) return EFI_COMPROMISED_DATA;
    for (I=12; I<4096; ++I) {
      if (I>=20 && I<24) continue;
      if (Open && ((I>=12 && I<20) || (I>=32 && I<36))) continue;
      if (Page[I]) return EFI_COMPROMISED_DATA;
    }
    *Returned=Handle;
    if (Register) FnuLog(L"FUXIM3 SMCI remote-object=%x; root register only", Handle);
#if FUXI_M3_SMCI_LOADER
    else FnuLog(L"FUXIM3 SMCI loader-object=%x; UID122 only", Handle);
#endif
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
#if FUXI_M3_SMCI_LOADER
  UINT32 Loader=0, Passed=0;
  CONST CHAR8 *Step="allocate";
#endif
  mSmciStatus=EFI_NOT_READY;
#if FUXI_M3_SMCI_LOADER
  FNU_STAGE("m3-smci-loader");
  FnuLog(L"FUXIM3 BATCH plan=root/open122/release-loader/release-env/delete; gated, no retry");
#else
  FNU_STAGE("m3-smci-root");
#endif
  FnuLog(L"FUXIM3 SMCI mode=%a; one register/release, no fallback",
         FUXI_M3_SMCI_OBJECT ? "object-cmd2" : "legacy-cmd0");
  if (gBS->AllocatePages(AllocateMaxAddress,EfiBootServicesData,2,&Raw)!=EFI_SUCCESS) {
    mSmciStatus=EFI_OUT_OF_RESOURCES;
    FnuLog(L"FUXIM3 SMCI page allocation failed; no call");
#if FUXI_M3_SMCI_LOADER
    FnuLog(L"FUXIM3 BATCH stop=allocate passed=0; no call");
#endif
    return;
  }
  Page=(UINT8 *)(UINTN)Raw;ZeroMem(Page,8192);FnuCacheCiv(&mOps,Page,8192);
  FnuLog(L"FUXIM3 SMCI page phys=%lx bytes=2000; no keys",(UINT64)Raw);
#if FUXI_M3_SMCI_LOADER
  Step="bridge-enable";
#endif
  mSmciStatus=FdpBuildBridgeEnable(Regs);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  FnuLog(L"FUXIM3 SMCI bridge-enable begin");FnuSmc64(Regs,&Out);
  FnuLog(L"FUXIM3 SMCI bridge-enable return a0=%lx a1=%lx a2=%lx a3=%lx",
         (UINT64)Out.Arg0,(UINT64)Out.Arg1,(UINT64)Out.Arg2,(UINT64)Out.Arg3);
  if (Out.Arg0 || Out.Arg1) { mSmciStatus=EFI_NOT_READY;goto Done; }
#if FUXI_M3_SMCI_LOADER
  Step="bridge-create";
#endif
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
#if FUXI_M3_SMCI_LOADER
  Step="root-register";
#endif
  mSmciStatus=SmciInvoke((UINT64)Raw,Page,1,1,&Object);
  if (EFI_ERROR(mSmciStatus)) goto Done;
#if FUXI_M3_SMCI_LOADER
  Passed|=1;
  FnuLog(L"FUXIM3 BATCH root-register=Success; continue loader-open");
  Step="loader-open";
  mSmciStatus=SmciInvoke((UINT64)Raw,Page,Object,2,&Loader);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  Passed|=2;
  FnuLog(L"FUXIM3 BATCH loader-open=Success; continue loader-release");
  Step="loader-release";
  mSmciStatus=SmciInvoke((UINT64)Raw,Page,Loader,0,&Ignored);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  FnuLog(L"FUXIM3 BATCH loader-release=Success handle=%x",Loader);
  Loader=0;Passed|=4;
  Step="environment-release";
#endif
  mSmciStatus=SmciInvoke((UINT64)Raw,Page,Object,0,&Ignored);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  FnuLog(L"FUXIM3 SMCI object-release=Success handle=%x",Object);
  Object=0;
#if FUXI_M3_SMCI_LOADER
  Passed|=8;Step="bridge-delete";
#endif
  ZeroMem(Page,8192);FnuCacheCiv(&mOps,Page,8192);
  mSmciStatus=FdpBuildBridgeDelete(Bridge,Regs);
  if (EFI_ERROR(mSmciStatus)) goto Done;
  FnuLog(L"FUXIM3 SMCI bridge-delete begin handle=%lx",Bridge);FnuSmc64(Regs,&Out);
  FnuLog(L"FUXIM3 SMCI bridge-delete return a0=%lx a1=%lx a2=%lx a3=%lx",
         (UINT64)Out.Arg0,(UINT64)Out.Arg1,(UINT64)Out.Arg2,(UINT64)Out.Arg3);
  mSmciStatus=Out.Arg0 ? EFI_NOT_READY : EFI_SUCCESS;
  if (!EFI_ERROR(mSmciStatus)) {
    Retain=FALSE;
#if FUXI_M3_SMCI_LOADER
    Passed|=16;Step="complete";
#endif
  }
Done:
#if FUXI_M3_SMCI_LOADER
  FnuLog(L"FUXIM3 BATCH stop=%a passed=%x env=%x loader=%x retained=%u",Step,Passed,Object,Loader,(UINT32)Retain);
#endif
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
