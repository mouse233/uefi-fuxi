// SPDX-License-Identifier: BSD-2-Clause-Patent
// M1 native UFS read-only diagnostics for the TWRP -> UEFI port. Adopts the
// controller state ABL left behind (no reset, no link restart), replaces the
// stopped request list with an owned DMA window, and reads GPT plus the first
// partition blocks through the M0 bounded readers. There is no write path, no
// key operation and no BlockIo publication; a timeout quarantines the window.
#include <Uefi.h>
#include <Protocol/EFIScm.h>
#include <Protocol/EFIQseecom.h>
#include <Library/ArmSmcLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/DebugLib.h>
#include <Library/IoLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/TimerLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include "UfsCore.h"
#include "UfsSha256.h"
#include "UfsReport.h"
#include "../../Include/Protocol/FuxiUfsReport.h"
#include "../FuxiDataProbeDxe/DataReadOnly.h"
#include "../FuxiDataProbeDxe/F2fsReadOnly.h"
#ifndef FUXI_M3_SCM_BRIDGE
#define FUXI_M3_SCM_BRIDGE 0
#endif
#if FUXI_M3_SCM_BRIDGE && !FUXI_M3_SCM_INFO
#error Bridge availability requires INFO self-query
#endif
#ifndef FUXI_M3_CRYPTO_CAP
#define FUXI_M3_CRYPTO_CAP 0
#endif
#ifndef FUXI_M3_SCM_INVOKE
#define FUXI_M3_SCM_INVOKE 0
#endif
#if FUXI_M3_SCM_INVOKE && !FUXI_M3_SCM_INFO
#error Invoke availability requires INFO self-query
#endif
#ifndef FUXI_M3_SCM_SUBJECTS
#define FUXI_M3_SCM_SUBJECTS 0
#endif
#if FUXI_M3_SCM_SUBJECTS && !FUXI_M3_SCM_INFO
#error ICE availability requires INFO self-query
#endif
#ifndef FUXI_M3_SCM_INFO
#define FUXI_M3_SCM_INFO 0
#endif
#ifndef FUXI_M3_BRIDGE_LARGE
#define FUXI_M3_BRIDGE_LARGE 0
#endif
#if FUXI_M3_BRIDGE_LARGE && (!FUXI_UFS_LUN4_KEYS || !FUXI_M3_BRIDGE_HLOS || !FUXI_M3_SCM_BRIDGE_CALL )
#error Large bridge requires LUN4 and HLOS bridge
#endif
#ifndef FUXI_UFS_LUN4_KEYS
#define FUXI_UFS_LUN4_KEYS 0
#endif
#if FUXI_UFS_LUN4_KEYS && !FUXI_UFS_DIAGNOSTIC_PARK
#error LUN4 keymaster diagnostic requires parked mode
#endif
#ifndef FUXI_UFS_M2_FILES
#define FUXI_UFS_M2_FILES 0
#endif
#ifndef FUXI_UFS_DIAGNOSTIC_PARK
#define FUXI_UFS_DIAGNOSTIC_PARK 0
#endif
#if FUXI_UFS_DIAGNOSTIC_PARK && !FUXI_UFS_M2_FILES
#error Diagnostic park requires the M2 diagnostic
#endif
#ifndef FUXI_M3_METADATA_KEY
#define FUXI_M3_METADATA_KEY 0
#endif
#if FUXI_M3_METADATA_KEY && !FUXI_UFS_M2_FILES
#error Metadata key discovery requires the M2 diagnostic
#endif
#if FUXI_M3_METADATA_KEY && !FUXI_UFS_DIAGNOSTIC_PARK
#error Metadata key discovery requires the parked diagnostic
#endif
#ifndef FUXI_M3_SCM_BRIDGE_CALL
#define FUXI_M3_SCM_BRIDGE_CALL 0
#endif
#if FUXI_M3_SCM_BRIDGE_CALL && !FUXI_M3_SCM_INFO
#error Bridge calls require the INFO self-query
#endif
#if FUXI_M3_SCM_BRIDGE_CALL && !FUXI_UFS_DIAGNOSTIC_PARK
#error Bridge calls require the parked diagnostic
#endif

#ifndef FUXI_M3_BRIDGE_HLOS
#define FUXI_M3_BRIDGE_HLOS 0
#endif
#if FUXI_M3_BRIDGE_HLOS && (!FUXI_M3_SCM_BRIDGE_CALL || FUXI_M3_BRIDGE_BLOB || FUXI_M3_SMC_CONTEXT)
#error HLOS bridge requires diagnostic with no blob/context
#endif
#ifndef FUXI_M3_BRIDGE_BLOB
#define FUXI_M3_BRIDGE_BLOB 0
#endif
#if FUXI_M3_BRIDGE_BLOB && (!FUXI_M3_SCM_BRIDGE_CALL || !FUXI_UFS_M2_FILES)
#error Bridge blob requires bridge calls and the parked M2 diagnostic
#endif

#ifndef FUXI_M3_SMCI_ROOT
#define FUXI_M3_SMCI_ROOT 0
#endif
#ifndef FUXI_M3_SMC_CONTEXT
#define FUXI_M3_SMC_CONTEXT 0
#endif
#if FUXI_M3_SMC_CONTEXT && !FUXI_M3_SMCI_ROOT
#error Context probe requires the parked root diagnostic configuration
#endif
#ifndef FUXI_M3_SMCI_OBJECT
#define FUXI_M3_SMCI_OBJECT 0
#endif
#if FUXI_M3_SMCI_OBJECT && !FUXI_M3_SMCI_ROOT
#error Object invoke mode requires the root diagnostic
#endif
#if FUXI_M3_SMCI_ROOT && (!FUXI_M3_SCM_BRIDGE_CALL || !FUXI_M3_SCM_INVOKE || !FUXI_UFS_DIAGNOSTIC_PARK)
#error SMCI root requires bridge, invoke availability and diagnostic park
#endif
#if FUXI_M3_SMCI_ROOT && (FUXI_M3_BRIDGE_BLOB || FUXI_M3_METADATA_KEY)
#error SMCI root must not read key blobs
#endif

#ifndef FUXI_M3_SMCI_LOADER
#define FUXI_M3_SMCI_LOADER 0
#endif
#if FUXI_M3_SMCI_LOADER && (!FUXI_M3_SMCI_ROOT || !FUXI_M3_SMCI_OBJECT || !FUXI_M3_BRIDGE_HLOS || FUXI_M3_SMC_CONTEXT)
#error Loader batch requires HLOS object root diagnostic, no context probe
#endif
#ifndef FUXI_M3_SMCI_LOOKUP
#define FUXI_M3_SMCI_LOOKUP 0
#endif
#if FUXI_M3_SMCI_LOOKUP && (!FUXI_M3_SMCI_LOADER || !FUXI_M3_SMCI_ROOT || !FUXI_M3_SMCI_OBJECT || !FUXI_M3_BRIDGE_HLOS || FUXI_M3_SMC_CONTEXT)
#error Lookup batch requires the HLOS loader batch and no context probe
#endif
#ifndef FUXI_M3_SMCI_LOAD
#define FUXI_M3_SMCI_LOAD 0
#endif
#if FUXI_M3_SMCI_LOAD && (!FUXI_M3_SMCI_LOADER || FUXI_M3_SMCI_LOOKUP || FUXI_M3_SMC_CONTEXT)
#error Load stage requires the loader batch, no lookup and no context probe
#endif
#if FUXI_M3_SMCI_LOAD && (!FUXI_M3_BRIDGE_LARGE || !FUXI_UFS_LUN4_KEYS)
#error Load stage requires the large bridge and the LUN4 keymaster input
#endif
// One load attempt per boot. The signed extent is read while the LUN4 queue is
// still live; the M3 stage runs after ShutdownQueue and cannot read it again.
#if FUXI_M3_SMCI_LOAD
#ifndef FUXI_M3_SMCI_TA_BYTES
#define FUXI_M3_SMCI_TA_BYTES 0x63058U
#endif
STATIC UINT8 *mTaImage = NULL;
STATIC UINTN mTaImageBytes = 0;
STATIC UINTN mTaImagePages = 0;
STATIC EFI_STATUS mTaImageStatus = EFI_NOT_READY;
#endif

#define FNU_POLLS(Microseconds) ((Microseconds) / 2U)
#define FNU_TIMEOUT_NOP         200000U
#define FNU_TIMEOUT_READ       1000000U
#define FNU_TIMEOUT_SSU         500000U
#define FNU_STOP_ATTEMPTS        10000U
// Stage markers go through the debug console (they appear on the on-screen
// boot log), so a reset localizes the faulting step without a photo of values.
STATIC CONST CHAR8 *mLastStage = "entry";
#define FNU_STAGE(Name) do { mLastStage = (Name); DEBUG((DEBUG_ERROR, "FUXIUFS stage: %a\n", (Name))); } while (0)
#ifndef FUXI_UFS_REPORT_HOLD_SECONDS
#define FUXI_UFS_REPORT_HOLD_SECONDS 0
#endif
STATIC FNU_REPORT mReport;
STATIC EFI_GUID mReportGuid = FUXI_UFS_REPORT_PROTOCOL_GUID;

// Value lines go to both consoles: ConOut (the graphics console) and the
// debug serial, which is the channel the on-screen boot log renders.
STATIC VOID FnuEmitLine(CONST CHAR16 *Line) {
  CHAR8 Ascii[320];
  UINTN I;
  Print(L"%s\r\n", Line);
  for (I = 0; I < sizeof(Ascii) - 1 && Line[I] != 0; ++I) Ascii[I] = (CHAR8)(Line[I] & 0xff);
  Ascii[I] = 0;
  DEBUG((DEBUG_ERROR, "%a\n", Ascii));
}

STATIC VOID FnuLog(CONST CHAR16 *Fmt, ...) {
  CHAR16 Buffer[320];
  VA_LIST Args;
  VA_START(Args, Fmt);
  UnicodeVSPrint(Buffer, sizeof(Buffer), Fmt, Args);
  VA_END(Args);
  FnuReportAppend(&mReport, Buffer);
  FnuEmitLine(Buffer);
}

// DXE-time protocol discovery only: no protocol method or secure call.
// NOT_FOUND here does not rule out a provider that would dispatch later.
STATIC VOID FnuInspectSecurityProtocols(VOID) {
  QCOM_SCM_PROTOCOL *Scm = NULL;
  QCOM_QSEECOM_PROTOCOL *Qsee = NULL;
  EFI_STATUS ScmStatus, QseeStatus;
  ScmStatus = gBS->LocateProtocol(&gQcomScmProtocolGuid, NULL, (VOID **)&Scm);
  QseeStatus = gBS->LocateProtocol(&gQcomQseecomProtocolGuid, NULL, (VOID **)&Qsee);
  FnuLog(L"FUXIM3 DXE protocols SCM=%r nonnull=%u QSEE=%r nonnull=%u",
         ScmStatus, (UINT32)(Scm != NULL), QseeStatus, (UINT32)(Qsee != NULL));
  FnuLog(L"FUXIM3 discovery only: no protocol methods or SMC; no decrypt");
}

#if FUXI_M3_SCM_INFO || FUXI_M3_SCM_BRIDGE_CALL
STATIC BOOLEAN mScmAvailable;
#if FUXI_M3_SMCI_ROOT
STATIC BOOLEAN mInvokeAvailable;
#endif
#endif
#if FUXI_M3_SCM_INFO
// A single non-mutating INFO/IS_CALL_AVAILABLE query, asking about itself.
// A synchronous SMC cannot be interrupted by a software timeout.
STATIC VOID FnuScmInfoProbe(VOID) {
  UINT64 Values[8];
  ARM_SMC_ARGS Args;
  BOOLEAN Available = FALSE;
  EFI_STATUS Status = FdpMakeAvailabilityQuery(FDP_SCM_INFO_AVAIL, TRUE, Values);
  if (EFI_ERROR(Status)) {
    FnuLog(L"FUXIM3 SCM64 INFO construct=%r; no call", Status);
    return;
  }
  ZeroMem(&Args, sizeof(Args));
  Args.Arg0 = (UINTN)Values[0];
  Args.Arg1 = (UINTN)Values[1];
  Args.Arg2 = (UINTN)Values[2];
  FnuLog(L"FUXIM3 SCM64 INFO begin (one call; no hardware timeout)");
  ArmCallSmc(&Args);
  Status = FdpDecodeAvailability(Args.Arg0, Args.Arg1, &Available);
  mScmAvailable = (BOOLEAN)(!EFI_ERROR(Status) && Available);
  FnuLog(L"FUXIM3 SCM64 INFO return a0=%lx a1=%lx decode=%r available=%u",
         (UINT64)Args.Arg0, (UINT64)Args.Arg1, Status, (UINT32)Available);
#if FUXI_M3_SCM_SUBJECTS || FUXI_M3_SCM_INVOKE || FUXI_M3_SCM_BRIDGE
  if (!EFI_ERROR(Status) && Available) {
    CONST UINT32 Subjects[] = {
#if FUXI_M3_SCM_SUBJECTS
      FDP_SCM_ICE_SET, FDP_SCM_ICE_CLEAR, FDP_SCM_ICE_DERIVE,
#endif
#if FUXI_M3_SCM_BRIDGE
      FDP_SCM_BRIDGE_ENABLE, FDP_SCM_BRIDGE_CREATE, FDP_SCM_BRIDGE_DELETE,
#endif
#if FUXI_M3_SCM_INVOKE
      FDP_SCM_INVOKE_LEGACY, FDP_SCM_INVOKE_CALLBACK, FDP_SCM_INVOKE_OBJECT,
#endif
    };
    UINTN I;
    for (I = 0; I < ARRAY_SIZE(Subjects); ++I) {
      Status = FdpMakeAvailabilityQuery(Subjects[I], TRUE, Values);
      if (EFI_ERROR(Status)) break;
      ZeroMem(&Args, sizeof(Args));
      Args.Arg0 = (UINTN)Values[0];
      Args.Arg1 = (UINTN)Values[1];
      Args.Arg2 = (UINTN)Values[2];
      FnuLog(L"FUXIM3 SCM64 subject=%08x begin", Subjects[I]);
      ArmCallSmc(&Args);
      Status = FdpDecodeAvailability(Args.Arg0, Args.Arg1, &Available);
      FnuLog(L"FUXIM3 SCM64 subject=%08x a0=%lx a1=%lx decode=%r available=%u",
             Subjects[I], (UINT64)Args.Arg0, (UINT64)Args.Arg1, Status, (UINT32)Available);
#if FUXI_M3_SMCI_ROOT
      if (Subjects[I] == (FUXI_M3_SMCI_OBJECT ? FDP_SCM_INVOKE_OBJECT : FDP_SCM_INVOKE_LEGACY))
        mInvokeAvailable = (BOOLEAN)(!EFI_ERROR(Status) && Available);
#endif
      if (EFI_ERROR(Status)) break;
    }
  }
#endif
}
#endif

STATIC VOID EFIAPI ReplayReport(VOID) {
  // Uses sealed text only: safe even when the transport is quarantined.
  FnuEmitLine(L"FUXIUFS CACHED REPORT BEGIN (no new UFS IO)");
  FnuReportReplay(&mReport, FnuEmitLine);
  if (mReport.Dropped || mReport.Truncated) {
    CHAR16 Warning[128];
    UnicodeSPrint(Warning, sizeof(Warning), L"FUXIUFS REPORT INCOMPLETE dropped=%u truncated=%u",
                  (UINT32)mReport.Dropped, (UINT32)mReport.Truncated);
    FnuEmitLine(Warning);
  }
  FnuEmitLine(L"FUXIUFS CACHED REPORT END; values are from pre-USB diagnostic");
}
STATIC FUXI_UFS_REPORT_PROTOCOL mReportProtocol = {FUXI_UFS_REPORT_REVISION, ReplayReport};

STATIC FNU_OPS mOps;
STATIC FNU_DEVICE mDev;
STATIC BOOLEAN mPoisoned;
STATIC BOOLEAN mReady;
STATIC BOOLEAN mSmmuConfigured;
STATIC UINTN mSmmuCb;
STATIC UINT64 mLastBlock;
STATIC VOID *mDma;
STATIC UINTN mDmaPages;

STATIC UINT32 FnuRead(FNU_OPS *Ops, UINT64 Phys) {
  (VOID)Ops;
  return MmioRead32((UINTN)Phys);
}

STATIC VOID FnuWrite(FNU_OPS *Ops, UINT64 Phys, UINT32 Value) {
  (VOID)Ops;
  MmioWrite32((UINTN)Phys, Value);
}

STATIC VOID FnuStall(FNU_OPS *Ops, UINTN Microseconds) {
  (VOID)Ops;
  MicroSecondDelay(Microseconds);
}

STATIC VOID FnuCacheCiv(FNU_OPS *Ops, VOID *Va, UINTN Bytes) {
  (VOID)Ops;
  WriteBackInvalidateDataCacheRange(Va, Bytes);
}

STATIC VOID FnuCacheInv(FNU_OPS *Ops, VOID *Va, UINTN Bytes) {
  (VOID)Ops;
  InvalidateDataCacheRange(Va, Bytes);
}

#include "M3BridgeBlob.inc"
#include "M3BridgeDiagnostic.inc"
#include "M3SmciDiagnostic.inc"
#include "M3SmcContext.inc"

STATIC UINT32 FnuSmmuRead(VOID *Context, UINTN Offset) {
  (VOID)Context;
  return MmioRead32((UINTN)(FNU_SMMU_BASE + Offset));
}

STATIC VOID FnuSmmuWrite(VOID *Context, UINTN Offset, UINT32 Value) {
  (VOID)Context;
  MmioWrite32((UINTN)(FNU_SMMU_BASE + Offset), Value);
}

// The window is page aligned and every cache callback range is 64-byte
// aligned, matching the proven device-memory line discipline.
STATIC EFI_STATUS AllocateDmaWindow(UINT64 FirmwareList, UINTN Pages, VOID **Virt,
                                    UINT64 *Phys) {
  EFI_PHYSICAL_ADDRESS Max = SIZE_4GB - 1;
  EFI_PHYSICAL_ADDRESS Raw = Max;
  if (gBS->AllocatePages(AllocateMaxAddress, EfiBootServicesData, Pages, &Raw) != EFI_SUCCESS) {
    return EFI_OUT_OF_RESOURCES;
  }
  // Never overlap the request list ABL left behind.
  if (FirmwareList != 0 &&
      Raw < FirmwareList + SIZE_16KB && FirmwareList < Raw + EFI_PAGES_TO_SIZE(Pages)) {
    gBS->FreePages(Raw, Pages);
    if (FirmwareList < EFI_PAGES_TO_SIZE(Pages)) return EFI_OUT_OF_RESOURCES;
    Raw = FirmwareList - 1;
    if (gBS->AllocatePages(AllocateMaxAddress, EfiBootServicesData, Pages, &Raw) != EFI_SUCCESS) {
      return EFI_OUT_OF_RESOURCES;
    }
  }
  *Virt = (VOID *)(UINTN)Raw;
  *Phys = Raw;
  return EFI_SUCCESS;
}

STATIC VOID PrintSha256(CONST CHAR16 *Label, CONST VOID *Data, UINTN Bytes) {
  FNU_SHA256_CTX Ctx;
  UINT8 Digest[32];
  CHAR16 Line[128];
  UINTN I, At = 0;
  FnuSha256Init(&Ctx);
  FnuSha256Update(&Ctx, Data, Bytes);
  FnuSha256Final(&Ctx, Digest);
  for (I = 0; Label[I] != 0 && At < 64; ++I) Line[At++] = Label[I];
  for (I = 0; I < 32 && At < 100; ++I) {
    At += (UINTN)UnicodeSPrint(Line + At, sizeof(Line) - At * sizeof(CHAR16),
                               L"%02x", (UINT32)Digest[I]);
  }
  Line[At] = 0;
  FnuLog(L"%s", Line);
}

STATIC EFI_STATUS FnuReadBlocksFdp(VOID *Context, UINT64 Lba, UINTN Blocks, VOID *Buffer) {
  if (!mReady || mPoisoned) return EFI_NOT_READY;
  if (Lba > mLastBlock || Blocks == 0 || Blocks - 1 > mLastBlock - Lba) {
    return EFI_INVALID_PARAMETER;
  }
  return FnuReadBlocks(&mDev, &mOps, Lba, Blocks, Buffer, FNU_POLLS(FNU_TIMEOUT_READ));
}

#if FUXI_UFS_LUN4_KEYS
// Restricted diagnostic: never selects a slot or publishes the partition.
typedef struct { UINT8 Lun; UINT64 Last; } FNU_DIAG_LUN;
STATIC EFI_STATUS FnuLun4Read(VOID *Context, UINT64 Lba, UINTN Blocks, VOID *Buffer) {
  FNU_DIAG_LUN *C = Context;
  if (!mReady || mPoisoned || C == NULL || C->Lun != 4) return EFI_NOT_READY;
  if (Blocks == 0 || Lba > C->Last || Blocks - 1 > C->Last - Lba) return EFI_INVALID_PARAMETER;
  return FnuReadBlocksLun(&mDev, &mOps, C->Lun, Lba, Blocks, Buffer, FNU_POLLS(FNU_TIMEOUT_READ));
}
STATIC EFI_STATUS FnuHashKeymaster(CONST FDP_DISK *Disk, CONST FDP_PARTITION *Part,
                                   CONST CHAR16 *Name, CONST UINT8 Expected[32], VOID *Scratch) {
  FNU_SHA256_CTX Ctx;
  UINT8 Digest[32];
  CHAR16 Line[128];
  UINTN I, At = 0;
  UINT64 Offset;
  EFI_STATUS Status;
  if (!Part->Present || Part->Last - Part->First + 1 != 128) return EFI_COMPROMISED_DATA;
  FnuSha256Init(&Ctx);
  for (Offset = 0; Offset < 128; Offset += 16) {
    Status = FdpReadPartition(Disk, Part, Offset, 16, Scratch);
    if (EFI_ERROR(Status)) return Status;
    FnuSha256Update(&Ctx, Scratch, 65536);
  }
  FnuSha256Final(&Ctx, Digest);
  for (I = 0; Name[I] && At < 64; ++I) Line[At++] = Name[I];
  for (I = 0; I < 32; ++I)
    At += (UINTN)UnicodeSPrint(Line + At, sizeof(Line) - At * sizeof(CHAR16), L"%02x", (UINT32)Digest[I]);
  Line[At] = 0;
  FnuLog(L"%s", Line);
  return CompareMem(Digest, Expected, 32) == 0 ? EFI_SUCCESS : EFI_COMPROMISED_DATA;
}
#if FUXI_M3_SMCI_LOAD
// Read the signed extent once, while the LUN4 queue is still live. Only the
// declared MBNv7 extent is kept: the partition tail past it is zero fill.
STATIC EFI_STATUS FnuLoadTaImage(CONST FDP_DISK *Disk, CONST FDP_PARTITION *Part) {
  EFI_PHYSICAL_ADDRESS Raw = SIZE_4GB - 1;
  UINTN Blocks = (FUXI_M3_SMCI_TA_BYTES + 4095U) / 4096U;
  UINTN Pages = EFI_SIZE_TO_PAGES(Blocks * 4096U);
  FNU_SHA256_CTX Ctx;
  UINT8 Digest[32];
  CHAR16 Line[128];
  UINTN I, At = 0;
  EFI_STATUS Status;
  if (mTaImage != NULL) return EFI_ALREADY_STARTED;
  if (!Part->Present || Part->Last - Part->First + 1 < Blocks) return EFI_COMPROMISED_DATA;
  if (gBS->AllocatePages(AllocateMaxAddress, EfiBootServicesData, Pages, &Raw) != EFI_SUCCESS)
    return EFI_OUT_OF_RESOURCES;
  mTaImage = (UINT8 *)(UINTN)Raw;
  ZeroMem(mTaImage, EFI_PAGES_TO_SIZE(Pages));
  Status = FdpReadPartition(Disk, Part, 0, Blocks, mTaImage);
  if (EFI_ERROR(Status)) {
    ZeroMem(mTaImage, EFI_PAGES_TO_SIZE(Pages));
    gBS->FreePages(Raw, Pages);
    mTaImage = NULL;
    return Status;
  }
  FnuSha256Init(&Ctx);
  FnuSha256Update(&Ctx, mTaImage, FUXI_M3_SMCI_TA_BYTES);
  FnuSha256Final(&Ctx, Digest);
  for (I = 0; I < 32; ++I)
    At += (UINTN)UnicodeSPrint(Line + At, sizeof(Line) - At * sizeof(CHAR16), L"%02x", (UINT32)Digest[I]);
  Line[At] = 0;
  mTaImageBytes = FUXI_M3_SMCI_TA_BYTES;
  mTaImagePages = Pages;
  FnuLog(L"FUXIM3 TA extent bytes=%x sha256=%s", (UINT32)mTaImageBytes, Line);
  return EFI_SUCCESS;
}
#endif
STATIC BOOLEAN mLun4Passed = FALSE;
STATIC BOOLEAN RunLun4Keys(VOID *Scratch) {
  FNU_DIAG_LUN Context = {4, 0};
  FDP_DISK Disk;
  FDP_PARTITIONS Parts;
  UINT32 Last, Block;
  EFI_STATUS Status;
  STATIC CONST UINT8 HashA[32] = {0x2f,0xc8,0x38,0xa8,0xf0,0xed,0x57,0x2e,0xc7,0x7b,0x7d,0xb2,0xfe,0x39,0xab,0x4e,0x81,0xd0,0xaa,0x03,0x8b,0xfa,0xd4,0x82,0xb8,0x80,0x87,0xa2,0x7b,0xf4,0x3c,0xc6};
  STATIC CONST UINT8 HashB[32] = {0xfe,0x18,0xa4,0x67,0xcb,0xbd,0x94,0x57,0xcc,0x8e,0x2e,0x4a,0x05,0x82,0x2f,0xf0,0x56,0x23,0x83,0x42,0x88,0x1c,0xfc,0x55,0x8a,0x04,0x5a,0xea,0x6d,0x46,0x7e,0xac};
  FnuLog(L"FUXILUN4 slot=unknown; no automatic slot selection");
  Status = FnuTestUnitReadyLun(&mDev, &mOps, 4, FNU_POLLS(FNU_TIMEOUT_NOP));
  FnuLog(L"FUXILUN4 tur=%r", Status);
  if (EFI_ERROR(Status) || mPoisoned) return FALSE;
  Status = FnuReadCapacityLun(&mDev, &mOps, 4, &Last, &Block, FNU_POLLS(FNU_TIMEOUT_READ));
  FnuLog(L"FUXILUN4 capacity=%r last=%x block=%u", Status, Last, Block);
  if (EFI_ERROR(Status) || mPoisoned || Block != 4096) return FALSE;
  Context.Last = Last;
  Disk.Context = &Context; Disk.Read = FnuLun4Read; Disk.BlockSize = Block; Disk.LastBlock = Last;
  Status = FdpReadGpt(&Disk, Scratch, FDP_SCRATCH_BYTES, &Parts);
  FnuLog(L"FUXILUN4 GPT=%r", Status);
  if (EFI_ERROR(Status) || mPoisoned) return FALSE;
  FnuLog(L"FUXILUN4 a=%u %lx..%lx b=%u %lx..%lx", (UINT32)Parts.KeymasterA.Present,
         Parts.KeymasterA.First, Parts.KeymasterA.Last, (UINT32)Parts.KeymasterB.Present,
         Parts.KeymasterB.First, Parts.KeymasterB.Last);
  if (!Parts.KeymasterA.Present || !Parts.KeymasterB.Present) return FALSE;
  Status = FnuHashKeymaster(&Disk, &Parts.KeymasterA, L"FUXILUN4 a-sha256=", HashA, Scratch);
  FnuLog(L"FUXILUN4 hash-a=%r", Status);
  if (EFI_ERROR(Status) || mPoisoned) return FALSE;
#if FUXI_M3_SMCI_LOAD
  mTaImageStatus = FnuLoadTaImage(&Disk, &Parts.KeymasterA);
  FnuLog(L"FUXIM3 TA read=%r bytes=%x", mTaImageStatus, (UINT32)mTaImageBytes);
  if (EFI_ERROR(mTaImageStatus)) return FALSE;
#endif
  Status = FnuHashKeymaster(&Disk, &Parts.KeymasterB, L"FUXILUN4 b-sha256=", HashB, Scratch);
  FnuLog(L"FUXILUN4 hash-b=%r", Status);
  return (BOOLEAN)(!EFI_ERROR(Status) && !mPoisoned);
}
#endif

// Stop the request list again so the controller is left idle with the
// doorbell clear; a poisoned transport is reported without register writes.
STATIC VOID ShutdownQueue(VOID) {
  UINT32 Doorbell, RunStop, Hcs, Is, TaskDoorbell;
  BOOLEAN Stopped;
  mReady = FALSE;
  if (mPoisoned) {
    FnuLog(L"FUXIUFS quarantined: DMA retained; no further register access");
    return;
  }
  if (!mPoisoned) {
    FnuWrite(&mOps, FNU_UFS_HC_BASE + FNU_REG_IE, 0);
    FnuWrite(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTRLRSR, 0);
    Stopped = FnuWaitRegister(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTRLRSR, 1, 0,
                              FNU_STOP_ATTEMPTS);
    Doorbell = FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTRLDBR);
    RunStop = FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTRLRSR);
    Hcs = FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_HCS);
    Is = FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_IS);
    TaskDoorbell = FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTMRLDBR);
    Stopped = (BOOLEAN)(Stopped && Doorbell == 0 && TaskDoorbell == 0 &&
                         (RunStop & 1) == 0 && (Is & FNU_UFS_FATAL_STATUS) == 0);
    FnuLog(L"FUXIUFS stop=%u db=%08x run=%x hcs=%08x is=%08x tdb=%08x\n",
          (UINT32)Stopped, Doorbell, RunStop, Hcs, Is, TaskDoorbell);
    if (!Stopped) {
      mPoisoned = TRUE;
      FnuLog(L"FUXIUFS stop proof failed: DMA retained; no handoff");
      return;
    }
  }

  if (mSmmuConfigured) {
    UINT32 Gfsr = FnuSmmuRead(NULL, 0x48);
    UINT32 Fsr = FnuSmmuRead(NULL, mSmmuCb + 0x58);
    UINT64 Far = (UINT64)FnuSmmuRead(NULL, mSmmuCb + 0x60) |
                 ((UINT64)FnuSmmuRead(NULL, mSmmuCb + 0x64) << 32);
    FnuLog(L"FUXIUFS SMMU gfsr=%08x fsr=%08x far=%lx\n", Gfsr, Fsr, Far);
  }
}

STATIC EFI_STATUS VerifyPartition(CONST FDP_DISK *Disk, CONST FDP_PARTITION *Partition,
                            CONST CHAR16 *Name, VOID *First, VOID *Repeat) {
  UINTN Completed = 0;
  EFI_STATUS Status;
  if (!Partition->Present) return EFI_NOT_FOUND;
  Status = FdpVerifyPartitionRead(Disk, Partition, 0, 1, First, Repeat, 4096, 3, &Completed);
  FnuLog(L"FUXIUFS %s independent-read-proof=%r reads=%u/3 distinct-buffers=1",
         Name, Status, (UINT32)Completed);
  if (!EFI_ERROR(Status)) PrintSha256(Name, First, 4096);
  return Status;
}

STATIC VOID InspectPartition(CONST FDP_DISK *Disk, CONST FDP_PARTITION *Partition,
                             CONST CHAR16 *Name, VOID *Scratch) {
  EFI_STATUS Status;
  FDP_F2FS_GEOMETRY Geometry;
  UINT64 Blocks, Bytes;
  if (!Partition->Present) {
    FnuLog(L"FUXIUFS %s: not found\n", Name);
    return;
  }
  Blocks = Partition->Last - Partition->First + 1;
  if (Blocks > MAX_UINT64 / Disk->BlockSize) {
    FnuLog(L"FUXIUFS %s: geometry overflow\n", Name);
    return;
  }
  Bytes = Blocks * Disk->BlockSize;
  // Signature/geometry inspection only; never a mount or file read.
  Status = FdpReadPartition(Disk, Partition, 0, 1, Scratch);
  if (!EFI_ERROR(Status)) Status = FdpInspectF2fs(Scratch, 4096, Bytes, &Geometry);
  FnuLog(L"FUXIUFS %s first-block F2FS-header=%r\n", Name, Status);
  if (!EFI_ERROR(Status)) {
    CONST UINT8 *S = (CONST UINT8 *)Scratch + 1024;
    UINT32 Feature = (UINT32)S[2180] | ((UINT32)S[2181] << 8) |
                     ((UINT32)S[2182] << 16) | ((UINT32)S[2183] << 24);
    UINT32 Payload = (UINT32)S[1664] | ((UINT32)S[1665] << 8) |
                     ((UINT32)S[1666] << 16) | ((UINT32)S[1667] << 24);
    FnuLog(L"FUXIUFS %s M2-input feature=%08x cp-payload=%u cp=%u nat=%u main=%u",
           Name, Feature, Payload, Geometry.CheckpointBlock, Geometry.NatBlock, Geometry.MainBlock);
  }
}

STATIC VOID SnapshotMappings(CONST CHAR16 *When) {
  UINT32 Idr0 = FnuSmmuRead(NULL, 0x20), Idr1 = FnuSmmuRead(NULL, 0x24);
  UINT32 Idr2 = FnuSmmuRead(NULL, 0x28), Count = Idr0 & 255, Banks = Idr1 & 255;
  UINT32 Pages = 1U << (((Idr1 >> 28) & 7) + 1), I, Matches = 0;
  FnuLog(L"FUXIUFS %s SMMU idr=%08x/%08x/%08x gfsr=%08x",
         When, Idr0, Idr1, Idr2, FnuSmmuRead(NULL, 0x48));
  if ((Idr1 & (1U << 31)) || Count == 0 || Banks < 2 || Banks > 128 ||
      Pages > 128 || (Pages + Banks) * 4096 > FNU_SMMU_SIZE) {
    FnuLog(L"FUXIUFS %s mapping snapshot: unsupported geometry", When);
    return;
  }
  if (Count > 128) Count = 128;
  for (I = 0; I < Count; ++I) {
    UINT32 Smr = FnuSmmuRead(NULL, 0x800 + 4 * I);
    UINT32 Mask = (Smr >> 16) & 0x7fff;
    if (!(Smr & 0x80000000U) || ((Smr ^ FNU_SMMU_STREAM) & 0xffff & ~Mask)) continue;
    ++Matches;
    if (Matches <= 4) {
      UINT32 S2Cr = FnuSmmuRead(NULL, 0xc00 + 4 * I), Bank = S2Cr & 255;
      FnuLog(L"FUXIUFS %s sid60 slot=%u smr=%08x s2cr=%08x", When, I, Smr, S2Cr);
      if (Bank < Banks) {
        UINTN Cb = (Pages + Bank) * 4096;
        FnuLog(L"FUXIUFS %s bank=%u sctlr=%08x cbar=%08x cba2r=%08x fsr=%08x",
               When, Bank, FnuSmmuRead(NULL, Cb), FnuSmmuRead(NULL, 0x1000 + 4 * Bank),
               FnuSmmuRead(NULL, 0x1800 + 4 * Bank), FnuSmmuRead(NULL, Cb + 0x58));
      }
    }
  }
  FnuLog(L"FUXIUFS %s sid60 matches=%u (first four shown)", When, Matches);
}

#include "M2Diagnostic.inc"
#include "M3KeyDiagnostic.inc"

STATIC VOID RunDiagnostic(VOID) {
  UINT32 Cap, Ver, Is, Hcs, Hce, Doorbell, TaskDoorbell, RunStop, Ahit;
  UINT32 Uic[5], I;
  UINT64 FirmwareList;
  CONST CHAR8 *Reason;
  EFI_STATUS Status;
  FNU_SMMU_PLAN Plan;
  CONST CHAR8 *SmmuError;
  UINT32 IsBefore, Power = 0, LastLba = 0, BlockBytes = 0;
  UINTN Attempt, TurAttempts = 0;

  mDev.HcPhys = FNU_UFS_HC_BASE;
  mDev.Poisoned = &mPoisoned;

  // Read-only clock report before anything is written.
  FNU_STAGE("gcc-report");
  FnuLog(L"FUXIUFS GCC gdsc=%08x memphy=%08x axi=%08x ahb=%08x unipro=%08x\n",
        FnuRead(&mOps, FNU_GCC_BASE + FNU_GCC_UFS_PHY_GDSCR),
        FnuRead(&mOps, FNU_GCC_BASE + FNU_GCC_MEM_PHY_GDSCR),
        FnuRead(&mOps, FNU_GCC_BASE + FNU_GCC_UFS_PHY_AXI),
        FnuRead(&mOps, FNU_GCC_BASE + FNU_GCC_UFS_PHY_AHB),
        FnuRead(&mOps, FNU_GCC_BASE + FNU_GCC_UFS_PHY_UNIPRO));
  FnuLog(L"FUXIUFS GCC txsym=%08x rxsym=%08x aux=%08x aggre=%08x\n",
        FnuRead(&mOps, FNU_GCC_BASE + FNU_GCC_UFS_PHY_TXSYM0),
        FnuRead(&mOps, FNU_GCC_BASE + FNU_GCC_UFS_PHY_RXSYM0),
        FnuRead(&mOps, FNU_GCC_BASE + FNU_GCC_UFS_PHY_AUX),
        FnuRead(&mOps, FNU_GCC_BASE + FNU_GCC_AGGRE_UFS_AXI));

  FNU_STAGE("hc-report");
  Cap = FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_CAP);
  Ver = FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_VER);
  Is = FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_IS);
  Hcs = FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_HCS);
  Hce = FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_HCE);
  Doorbell = FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTRLDBR);
  TaskDoorbell = FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTMRLDBR);
  RunStop = FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTRLRSR);
  Ahit = FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_AHIT);
  FirmwareList = ((UINT64)FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTRLBAU) << 32) |
                 FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTRLBA);
  for (I = 0; I < 5; ++I) Uic[I] = FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_UIC(I));
  FnuLog(L"FUXIUFS HC cap=%08x ver=%08x hcs=%08x hce=%08x is=%08x\n",
        Cap, Ver, Hcs, Hce, Is);
  FnuLog(L"FUXIUFS HC db=%08x tdb=%08x run=%x ahit=%x list=%lx\n",
        Doorbell, TaskDoorbell, RunStop, Ahit, FirmwareList);
  FnuLog(L"FUXIUFS UIC pa=%08x a1=%08x a2=%08x a3=%08x r=%08x\n",
        Uic[0], Uic[1], Uic[2], Uic[3], Uic[4]);

#if FUXI_M3_CRYPTO_CAP
  {
    FNU_CRYPTO_CAP_REPORT Crypto;
    FNU_STAGE("crypto-capabilities-read-only");
    Status = FnuReadCryptoCapabilities(&mOps, Cap, Hce, &Crypto);
    FnuLog(L"FUXIM3 crypto-cap status=%r ccap=%08x advertised=%u read=%u",
           Status, Crypto.Ccap, Crypto.AdvertisedCount, Crypto.EntryCount);
    for (I = 0; I < Crypto.EntryCount; ++I)
      FnuLog(L"FUXIM3 crypto-cap[%u]=%08x", I, Crypto.Entries[I]);
    if (!EFI_ERROR(Status)) {
      UINT32 XtsIndex;
      Status = FnuFindXts4096Capability(&Crypto, &XtsIndex);
      FnuLog(L"FUXIM3 crypto-xts4096 select=%r index=%u", Status, XtsIndex);
    }
  }
#endif

  SnapshotMappings(L"before");

  // Idle gate: refuse to touch the controller unless it matches the state the
  // proven takeover accepted (HCE set, HCS low nibble set, both doorbells
  // clear, no fatal status).
  FNU_STAGE("idle-gate");
  Reason = FnuQueueStopPlan(Hce, Hcs, Doorbell, TaskDoorbell, Is);
  if (Reason != NULL) {
    FnuLog(L"FUXIUFS idle: %a\n", Reason);
    return;
  }

  FNU_STAGE("dma-alloc");
  mDmaPages = EFI_SIZE_TO_PAGES(FNU_DMA_BYTES);
  Status = AllocateDmaWindow(FirmwareList, mDmaPages, &mDma, &mDev.DmaPhys);
  if (EFI_ERROR(Status)) {
    FnuLog(L"FUXIUFS DMA window=%r\n", Status);
    return;
  }
  mDev.Dma = mDma;
  FnuLog(L"FUXIUFS DMA phys=%lx bytes=%x\n", mDev.DmaPhys, (UINT32)FNU_DMA_BYTES);
  ZeroMem(mDma, FNU_DMA_BYTES);
  FnuCacheCiv(&mOps, mDma, FNU_DMA_BYTES);

  FNU_STAGE("stop-queue");
  FnuWrite(&mOps, FNU_UFS_HC_BASE + FNU_REG_IE, 0);
  FnuWrite(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTRLRSR, 0);
  if (!FnuWaitRegister(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTRLRSR, 1, 0, FNU_STOP_ATTEMPTS)) {
    FnuLog(L"FUXIUFS stop: request list did not stop\n");
    return;
  }

  FNU_STAGE("smmu-plan");
  Plan = FnuPlanSmmuFrom(FNU_SMMU_STREAM, mDev.DmaPhys, FNU_DMA_BYTES, NULL, FnuSmmuRead, 1);
  if (Plan.Error != NULL) {
    FnuLog(L"FUXIUFS SMMU plan: %a slot=%x bank=%u\n", Plan.Error, Plan.Slot, Plan.Bank);
    return;
  }
  FnuLog(L"FUXIUFS selected bank=%u slot=%u before sctlr=%08x cbar=%08x cba2r=%08x",
         Plan.Bank, Plan.Slot, FnuSmmuRead(NULL, (Plan.Pages + Plan.Bank) * 4096),
         FnuSmmuRead(NULL, 0x1000 + 4 * Plan.Bank), FnuSmmuRead(NULL, 0x1800 + 4 * Plan.Bank));
  SmmuError = FnuConfigureSmmu(&Plan, FNU_SMMU_STREAM, NULL, FnuSmmuRead, FnuSmmuWrite);
  if (SmmuError != NULL) {
    FnuLog(L"FUXIUFS SMMU configure: %a\n", SmmuError);
    return;
  }
  mSmmuConfigured = TRUE;
  mSmmuCb = (Plan.Pages + Plan.Bank) * 4096;
  FnuLog(L"FUXIUFS SMMU slot=%u bank=%u reuse=%u pages=%u smr=%08x s2cr=%08x\n",
        Plan.Slot, Plan.Bank, (UINT32)Plan.Reuse, Plan.Pages,
        FnuSmmuRead(NULL, 0x800 + 4 * Plan.Slot), FnuSmmuRead(NULL, 0xc00 + 4 * Plan.Slot));
  FNU_STAGE("start-queue");
  FnuWrite(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTRLBA, (UINT32)mDev.DmaPhys);
  FnuWrite(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTRLBAU, (UINT32)(mDev.DmaPhys >> 32));
  if (FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTRLBA) != (UINT32)mDev.DmaPhys ||
      FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTRLBAU) != (UINT32)(mDev.DmaPhys >> 32)) {
    FnuLog(L"FUXIUFS start: request list address readback\n");
    return;
  }
  IsBefore = FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_IS);
  FnuWrite(&mOps, FNU_UFS_HC_BASE + FNU_REG_IS, IsBefore);
  FnuWrite(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTRLRSR, 1);
  if (!FnuWaitRegister(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTRLRSR, 1, 1, FNU_STOP_ATTEMPTS) ||
      !FnuWaitRegister(&mOps, FNU_UFS_HC_BASE + FNU_REG_HCS, 3, 3, FNU_STOP_ATTEMPTS)) {
    FnuLog(L"FUXIUFS start: request list not ready hcs=%08x\n",
          FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_HCS));
    return;
  }

  FNU_STAGE("nop");
  Status = FnuNop(&mDev, &mOps, FNU_POLLS(FNU_TIMEOUT_NOP));
  FnuLog(L"FUXIUFS nop=%r\n", Status);
  if (EFI_ERROR(Status)) {
    ShutdownQueue();
    return;
  }
  FNU_STAGE("power-query");
  Status = FnuQueryRead(&mDev, &mOps, 0x03, 0x02, &Power, FNU_POLLS(FNU_TIMEOUT_NOP));
  FnuLog(L"FUXIUFS power-query=%r mode=%02x\n", Status, Power);
  if (EFI_ERROR(Status)) {
    ShutdownQueue();
    return;
  }
  if ((Power & 0xff) != 0x11) {
    // START STOP UNIT, power condition ACTIVE, to the device well-known LU
    // (as Linux resumes); no user LUN and no user data touched.
    Status = FnuStartStopUnit(&mDev, &mOps, FNU_POLLS(FNU_TIMEOUT_SSU));
    FnuLog(L"FUXIUFS wake-ssu=%r\n", Status);
    if (EFI_ERROR(Status)) {
      ShutdownQueue();
      return;
    }
    MicroSecondDelay(50000);
  }
  FNU_STAGE("lun0-tur");
  Status = EFI_NOT_READY;
  for (Attempt = 0; Attempt < 20 && !mPoisoned; ++Attempt) {
    Status = FnuTestUnitReady(&mDev, &mOps, FNU_POLLS(FNU_TIMEOUT_NOP));
    TurAttempts = Attempt + 1;
    if (!EFI_ERROR(Status)) break;
    MicroSecondDelay(10000);
  }
  FnuLog(L"FUXIUFS lun0-tur=%r attempts=%u\n", Status, (UINT32)TurAttempts);
  if (EFI_ERROR(Status)) {
    ShutdownQueue();
    return;
  }
  FNU_STAGE("capacity");
  Status = FnuReadCapacity(&mDev, &mOps, &LastLba, &BlockBytes, FNU_POLLS(FNU_TIMEOUT_READ));
  FnuLog(L"FUXIUFS capacity=%r last=%x block=%u\n", Status, LastLba, BlockBytes);
  if (EFI_ERROR(Status)) {
    ShutdownQueue();
    return;
  }
  if (BlockBytes != 4096) {
    FnuLog(L"FUXIUFS unexpected LUN0 block size; no GPT read\n");
    ShutdownQueue();
    return;
  }
  mLastBlock = LastLba;
  mReady = TRUE;

  FNU_STAGE("gpt");
  {
    FDP_DISK Disk;
    FDP_PARTITIONS Parts;
    VOID *Scratch;
    VOID *Repeat;
    Disk.Context = &mDev;
    Disk.Read = FnuReadBlocksFdp;
    Disk.BlockSize = 4096;
    Disk.LastBlock = mLastBlock;
    Scratch = AllocateAlignedPages(EFI_SIZE_TO_PAGES(FDP_SCRATCH_BYTES), 4096);
    if (Scratch == NULL) {
      FnuLog(L"FUXIUFS scratch allocation failed\n");
      ShutdownQueue();
      return;
    }
    Repeat = AllocateAlignedPages(1, 4096);
    if (Repeat == NULL) {
      FreeAlignedPages(Scratch, EFI_SIZE_TO_PAGES(FDP_SCRATCH_BYTES));
      ShutdownQueue();
      return;
    }
    Status = FdpReadGpt(&Disk, Scratch, FDP_SCRATCH_BYTES, &Parts);
    FnuLog(L"FUXIUFS GPT=%r\n", Status);
    if (!EFI_ERROR(Status)) {
      FnuLog(L"FUXIUFS metadata=%lx..%lx userdata=%lx..%lx\n",
            Parts.Metadata.First, Parts.Metadata.Last,
            Parts.Userdata.First, Parts.Userdata.Last);
      if (Parts.Userdata.Present) {
        Status = FnuReadBlocksFdp(&mDev, Parts.Userdata.First, 1, Scratch);
        if (!EFI_ERROR(Status)) {
          UINT8 *Block = Scratch;
          UINT32 Magic0 = Block[0] | (Block[1] << 8) | (Block[2] << 16) | ((UINT32)Block[3] << 24);
          UINT32 Magic1 = Block[4] | (Block[5] << 8) | (Block[6] << 16) | ((UINT32)Block[7] << 24);
          UINT32 Ext4 = (UINT32)Block[1080] | ((UINT32)Block[1081] << 8);
          FnuLog(L"FUXIUFS userdata block0 magic=%08x %08x ext4magic=%04x\n",
                Magic0, Magic1, Ext4);
          FnuLog(L"FUXIUFS (XNU 2026-10-23 observed magic f673c25f 7086bec0)\n");
          PrintSha256(L"userdata-first-block-sha256 ", Scratch, 4096);
        } else {
          FnuLog(L"FUXIUFS userdata first block=%r\n", Status);
        }
      }
      if (Parts.Metadata.Present) {
        Status = FnuReadBlocksFdp(&mDev, Parts.Metadata.First, 1, Scratch);
        if (!EFI_ERROR(Status)) {
          PrintSha256(L"metadata-first-block-sha256 ", Scratch, 4096);
        } else {
          FnuLog(L"FUXIUFS metadata first block=%r\n", Status);
        }
      }
      FNU_STAGE("independent-reads");
      Status = VerifyPartition(&Disk, &Parts.Metadata, L"metadata", Scratch, Repeat);
      if (EFI_ERROR(Status)) goto ReleaseScratch;
      Status = VerifyPartition(&Disk, &Parts.Userdata, L"userdata", Scratch, Repeat);
      if (EFI_ERROR(Status)) goto ReleaseScratch;
      InspectPartition(&Disk, &Parts.Metadata, L"metadata", Scratch);
      InspectPartition(&Disk, &Parts.Userdata, L"userdata", Scratch);
#if FUXI_UFS_M2_FILES
      RunM2(&Disk, &Parts.Metadata, Scratch, Repeat);
#if FUXI_UFS_LUN4_KEYS
      if (!mPoisoned && !EFI_ERROR(mM2Status)) { FNU_STAGE("lun4-keymaster"); mLun4Passed=RunLun4Keys(Scratch); }
      else FnuLog(L"FUXILUN4 skipped: M2 failed or DMA quarantined");
#endif
#endif
#if FUXI_M3_METADATA_KEY
      RunM3Key(&Disk, &Parts.Metadata, Scratch, Repeat);
#endif
#if FUXI_M3_BRIDGE_BLOB
      if (!mPoisoned && Parts.Metadata.Present && mScmAvailable)
        FnuBridgeCallProbe(&Disk, &Parts.Metadata, Scratch, mM3BlobExpectedSha);
      else FnuLog(L"FUXIM3 BLOB skipped: UFS/metadata/INFO unavailable");
#endif
    }
ReleaseScratch:
    ZeroMem(Repeat, 4096);
    FreeAlignedPages(Repeat, 1);
    ZeroMem(Scratch, EFI_PAGES_TO_SIZE(EFI_SIZE_TO_PAGES(FDP_SCRATCH_BYTES)));
    FreeAlignedPages(Scratch, EFI_SIZE_TO_PAGES(FDP_SCRATCH_BYTES));
  }
  FNU_STAGE("shutdown");
  ShutdownQueue();
}

EFI_STATUS EFIAPI FuxiNativeUfsDxeEntry(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
  DEBUG((DEBUG_ERROR, "FUXIUFS: entry reached\n"));
  mOps.Context = NULL;
  mOps.Read = FnuRead;
  mOps.Write = FnuWrite;
  mOps.Stall = FnuStall;
  mOps.CacheCleanInvalidate = FnuCacheCiv;
  mOps.CacheInvalidate = FnuCacheInv;
  (VOID)ImageHandle;
  (VOID)SystemTable;
  // Runs at DXE dispatch, ahead of the USB receiver: the receiver-only
  // candidate parks in its entry after the 180 s window and never reaches
  // ReadyToBoot, and the topmost SMMU context bank must stay untouched until
  // the receiver's route trial claims it.
  FnuLog(L"\nFUXIUFS M1: native UFS read-only takeover (diagnostic)");
#if FUXI_UFS_DIAGNOSTIC_PARK
  // Diagnostic residence is intentional; disable the UEFI watchdog before IO.
  FnuLog(L"FUXIM2 watchdog-disable=%r",gBS->SetWatchdogTimer(0,0,0,NULL));
#endif
  FnuInspectSecurityProtocols();
#if FUXI_M3_SCM_INFO
  FnuScmInfoProbe();
#endif
  RunDiagnostic();
#if FUXI_M3_SCM_BRIDGE_CALL && !FUXI_M3_BRIDGE_BLOB && !FUXI_M3_SMCI_ROOT
#if FUXI_M3_BRIDGE_LARGE
  if (!mPoisoned && mScmAvailable && mLun4Passed) FnuBridgeCallProbe(NULL, NULL, NULL, NULL);
  else FnuLog(L"FUXIM3 BRIDGE skipped: LUN4/INFO/queue not ready");
#else
  if (!mPoisoned && mScmAvailable) FnuBridgeCallProbe(NULL, NULL, NULL, NULL);
  else FnuLog(L"FUXIM3 BRIDGE skipped: UFS/INFO not ready");
#endif
#endif
#if FUXI_M3_SMC_CONTEXT
  {
    UINT64 El, Daif;
    __asm__ __volatile__("mrs %0, CurrentEL" : "=r"(El));
    __asm__ __volatile__("mrs %0, DAIF" : "=r"(Daif));
    (VOID)mInvokeAvailable;
    if (!mPoisoned) FnuSmcContextProbe(El,Daif);
    else FnuLog(L"FUXIM3 CTX skipped: UFS poisoned");
  }
#elif FUXI_M3_SMCI_ROOT
  // Invoke after the existing UFS shutdown, with no outstanding read DMA.
  if (!mPoisoned && mScmAvailable && mInvokeAvailable
#if FUXI_M3_BRIDGE_LARGE
      && mLun4Passed
#endif
      ) {
    UINT64 El, Daif;
    __asm__ __volatile__("mrs %0, CurrentEL" : "=r"(El));
    __asm__ __volatile__("mrs %0, DAIF" : "=r"(Daif));
    FnuLog(L"FUXIM3 SMCI context CurrentEL=%lx DAIF=%lx",El,Daif);
    FnuSmciRootProbe();
  }
  else FnuLog(L"FUXIM3 SMCI skipped: UFS/INFO/invoke availability not ready");
#endif
  FnuLog(L"FUXIUFS final stage=%a poisoned=%u ready=%u smmu-configured=%u",
         mLastStage, (UINT32)mPoisoned, (UINT32)mReady, (UINT32)mSmmuConfigured);
  if (!mPoisoned) {
    FnuLog(L"FUXIUFS after HC db=%08x tdb=%08x run=%x hcs=%08x is=%08x",
           FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTRLDBR),
           FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTMRLDBR),
           FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_UTRLRSR),
           FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_HCS),
           FnuRead(&mOps, FNU_UFS_HC_BASE + FNU_REG_IS));
    SnapshotMappings(L"after");
  }
#if FUXI_M3_METADATA_KEY
  FnuLog(L"FUXIM3 KEY END: result=%r files=%u; metadata key read only, no decrypt",
         mM3KeyStatus,(UINT32)mM3KeyFiles);
#endif
#if FUXI_UFS_M2_FILES
  FnuLog(L"FUXIM2 END: file-result=%r; decrypt=UNIMPLEMENTED handoff=0",mM2Status);
#else
  FnuLog(L"FUXIUFS END: metadata-decrypt=UNIMPLEMENTED file-read=UNIMPLEMENTED\n");
#endif
  {
    EFI_HANDLE ReportHandle = NULL;
    EFI_STATUS PublishStatus;
    UINTN Seconds;
#if FUXI_UFS_DIAGNOSTIC_PARK
    FnuLog(L"FUXIM2 PARK: no USB receiver; no handoff");
#endif
#if !FUXI_UFS_DIAGNOSTIC_PARK
    FnuLog(L"FUXIUFS photo hold=%u seconds before USB; final report replays at receiver park",
           (UINT32)FUXI_UFS_REPORT_HOLD_SECONDS);
#endif
    mReport.Sealed = TRUE;
    PublishStatus = gBS->InstallProtocolInterface(&ReportHandle, &mReportGuid,
                                                 EFI_NATIVE_INTERFACE, &mReportProtocol);
    ReplayReport();
    if (EFI_ERROR(PublishStatus)) {
      DEBUG((DEBUG_ERROR, "FUXIUFS report publish failed: %r; final replay unavailable\n", PublishStatus));
    }
    for (Seconds = 0; Seconds < FUXI_UFS_REPORT_HOLD_SECONDS; ++Seconds) MicroSecondDelay(1000000);
  }
#if FUXI_UFS_DIAGNOSTIC_PARK
  // APRIORI dispatch cannot proceed into UsbfnDwc3Dxe/FuxiUsbRamDxe.
  // No register access or new UFS IO occurs in this residence loop.
  for (;;) MicroSecondDelay(1000000);
#endif
  DEBUG((DEBUG_INFO, "FUXIUFS M1 completed; no decryptor, no BlockIo publication\n"));
  return EFI_SUCCESS;
}
