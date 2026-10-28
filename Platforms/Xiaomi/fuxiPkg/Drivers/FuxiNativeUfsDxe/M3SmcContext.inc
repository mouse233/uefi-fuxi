// SPDX-License-Identifier: BSD-2-Clause-Patent
// A read-only standard INFO control. No bridge, object, key or memory pointer.
#if FUXI_M3_SMC_CONTEXT
STATIC VOID FnuSmcContextProbe(UINT64 CurrentEl, UINT64 Daif) {
  UINT64 Regs[8]; ARM_SMC_ARGS Out;
  BOOLEAN Available=FALSE;
  EFI_STATUS Status;
  FNU_STAGE("m3-smc-context");
  FnuLog(L"FUXIM3 CTX CurrentEL=%lx DAIF=%lx fast-info=%u",CurrentEl,Daif,(UINT32)mScmAvailable);
  if (!mScmAvailable) { FnuLog(L"FUXIM3 CTX skipped: fast INFO unavailable");return; }
  Status=FdpMakeAvailabilityQuery(FDP_SCM_INFO_AVAIL,TRUE,Regs);
  if (EFI_ERROR(Status)) return;
  // Same INFO self-query fields as the proven fast C2000601, changing only
  // the call-type bit. Support for this standard variant is not presumed.
  Regs[0]&=~0x80000000ULL;
  FnuLog(L"FUXIM3 CTX std-info begin x0=%lx x1=%lx subject=%lx; one call",Regs[0],Regs[1],Regs[2]);
  FnuSmc64(Regs,&Out);
  Status=FdpDecodeAvailability(Out.Arg0,Out.Arg1,&Available);
  FnuLog(L"FUXIM3 CTX std-info return a0=%lx a1=%lx a2=%lx a3=%lx",
         (UINT64)Out.Arg0,(UINT64)Out.Arg1,(UINT64)Out.Arg2,(UINT64)Out.Arg3);
  FnuLog(L"FUXIM3 CTX decode=%r available=%u; availability only",Status,(UINT32)Available);
  FnuLog(L"FUXIM3 CTX END: no bridge, no objects, no key, no retry");
}
#endif
