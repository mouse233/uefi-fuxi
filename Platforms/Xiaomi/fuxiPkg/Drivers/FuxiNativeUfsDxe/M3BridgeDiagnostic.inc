// SPDX-License-Identifier: BSD-2-Clause-Patent
#if FUXI_M3_SCM_BRIDGE_CALL
// Enable/create/delete with explicit ownership: a registered page is retained
// until delete succeeds. Every synchronous SMC logs before entering secure world.
STATIC VOID FnuSmc64(CONST UINT64 Regs[8], ARM_SMC_ARGS *Out) {
  ZeroMem(Out, sizeof(*Out));
  Out->Arg0 = (UINTN)Regs[0];
  Out->Arg1 = (UINTN)Regs[1];
  Out->Arg2 = (UINTN)Regs[2];
  Out->Arg3 = (UINTN)Regs[3];
  Out->Arg4 = (UINTN)Regs[4];
  Out->Arg5 = (UINTN)Regs[5];
  Out->Arg6 = (UINTN)Regs[6];
  Out->Arg7 = (UINTN)Regs[7];
  ArmCallSmc(Out);
}

#if !FUXI_M3_SMCI_ROOT
STATIC VOID FnuBridgeCallProbe(CONST FDP_DISK *Disk,
                               CONST FDP_PARTITION *Metadata, VOID *Work,
                               CONST UINT8 *ExpectedSha) {
  EFI_PHYSICAL_ADDRESS Raw = SIZE_4GB - 1;
  VOID *Page;
  UINT64 Regs[8];
  ARM_SMC_ARGS Out;
  EFI_STATUS Status;
  UINT64 Handle = 0;
  BOOLEAN Created = FALSE;
  EFI_STATUS BlobStatus = EFI_SUCCESS;
  UINTN Pages = 2; // Match the two-page input/output range needed by C2.
  UINTN Bytes = EFI_PAGES_TO_SIZE(Pages);
  (VOID)Disk; (VOID)Metadata; (VOID)Work; (VOID)ExpectedSha;

  FNU_STAGE("m3-bridge-standard");
  FnuLog(L"FUXIM3 BRIDGE ABI=standard64 status=a0 service=a1 handle=a2; no objects");
  if (gBS->AllocatePages(AllocateMaxAddress, EfiBootServicesData, Pages, &Raw) != EFI_SUCCESS) {
    FnuLog(L"FUXIM3 BRIDGE page=allocation-failed; no SMC");
    return;
  }
  Page = (VOID *)(UINTN)Raw;
  ZeroMem(Page, Bytes);
  FnuCacheCiv(&mOps, Page, Bytes);
  FnuLog(L"FUXIM3 BRIDGE page phys=%lx bytes=%x", (UINT64)Raw, (UINT32)Bytes);

  Status = FdpBuildBridgeEnable(Regs);
  if (EFI_ERROR(Status)) {
    FnuLog(L"FUXIM3 BRIDGE enable construct=%r; no call", Status);
    goto Release;
  }
  FnuLog(L"FUXIM3 BRIDGE enable begin x0=%lx x1=%lx (no hardware timeout)",
         Regs[0], Regs[1]);
  FnuSmc64(Regs, &Out);
  FnuLog(L"FUXIM3 BRIDGE enable return a0=%lx a1=%lx a2=%lx a3=%lx",
         (UINT64)Out.Arg0, (UINT64)Out.Arg1, (UINT64)Out.Arg2, (UINT64)Out.Arg3);
  if (Out.Arg0 != 0 || Out.Arg1 != 0) goto Release;

  Status = FdpBuildBridgeCreate((UINT64)Raw, Bytes, 0, 0, Regs);
  if (EFI_ERROR(Status)) {
    FnuLog(L"FUXIM3 BRIDGE create construct=%r; no call", Status);
    goto Release;
  }
  FnuLog(L"FUXIM3 BRIDGE create begin x0=%lx arg0=%lx arg1=%lx arg2=%lx arg3=%lx",
         Regs[0], Regs[2], Regs[3], Regs[4], Regs[5]);
  // Once secure world has seen the page address, retain it on any unknown
  // create result (including an interrupted SMC) until deletion is proven.
  Created = TRUE;
  FnuSmc64(Regs, &Out);
  FnuLog(L"FUXIM3 BRIDGE create return a0=%lx a1=%lx a2=%lx a3=%lx",
         (UINT64)Out.Arg0, (UINT64)Out.Arg1, (UINT64)Out.Arg2, (UINT64)Out.Arg3);
  Status = FdpDecodeBridgeCreate(Out.Arg0, Out.Arg1, Out.Arg2, &Handle);
  if (EFI_ERROR(Status)) {
    FnuLog(L"FUXIM3 BRIDGE create decode=%r; no delete", Status);
    goto Release;
  }

#if FUXI_M3_BRIDGE_BLOB
  BlobStatus = FnuBridgeReadBlob(Disk, Metadata, Work, Page, Bytes, ExpectedSha);
  // Erase the blob and publish the wipe before removing the registration.
  ZeroMem(Page, Bytes);
  FnuCacheCiv(&mOps, Page, Bytes);
#endif
  Status = FdpBuildBridgeDelete(Handle, Regs);
  if (EFI_ERROR(Status)) {
    FnuLog(L"FUXIM3 BRIDGE delete construct=%r; no call", Status);
    goto Release;
  }
  FnuLog(L"FUXIM3 BRIDGE delete begin handle=%lx", Handle);
  FnuSmc64(Regs, &Out);
  FnuLog(L"FUXIM3 BRIDGE delete return a0=%lx a1=%lx a2=%lx a3=%lx",
         (UINT64)Out.Arg0, (UINT64)Out.Arg1, (UINT64)Out.Arg2, (UINT64)Out.Arg3);
  Status = (Out.Arg0 == 0) ? EFI_SUCCESS : EFI_NOT_READY;
  if (!EFI_ERROR(Status)) Created = FALSE;
#if FUXI_M3_BRIDGE_BLOB
  FnuLog(L"FUXIM3 BLOB result=%r delete=%r handle=%lx; no TA, no decrypt",
         BlobStatus, Status, Handle);
#else
  (VOID)BlobStatus;
  FnuLog(L"FUXIM3 BRIDGE result=%r handle=%lx; closed loop, no key, no TA, no decrypt",
         Status, Handle);
#endif
Release:
  if (Created) {
    FnuLog(L"FUXIM3 BRIDGE retained: create/delete unresolved handle=%lx bytes=%x",
           Handle, (UINT32)Bytes);
  } else {
    ZeroMem(Page, Bytes);
    FnuCacheCiv(&mOps, Page, Bytes);
    gBS->FreePages(Raw, Pages);
    FnuLog(L"FUXIM3 BRIDGE released bytes=%x", (UINT32)Bytes);
  }
}
#endif
#endif
