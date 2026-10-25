// SPDX-License-Identifier: BSD-2-Clause-Patent
// M0/M1 diagnostics for the TWRP -> UEFI port, not a /data decryptor.
#include <Uefi.h>
#include <Guid/EventGroup.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DevicePath.h>
#include <Protocol/EFIScm.h>
#include <Protocol/EFIQseecom.h>
#include <Library/ArmSmcLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include "DataReadOnly.h"

#ifndef FUXI_DATA_SCM_QUERY
#define FUXI_DATA_SCM_QUERY 0
#endif

typedef struct {
  EFI_BLOCK_IO_PROTOCOL *Io;
  UINT32 MediaId;
  UINT32 BlockSize;
  UINT64 LastBlock;
} FDP_EFI_DISK;
STATIC EFI_EVENT mReadyEvent;
STATIC BOOLEAN mRan;

STATIC EFI_STATUS ReadEfi(VOID *Context, UINT64 Lba, UINTN Blocks, VOID *Buffer) {
  FDP_EFI_DISK *Disk = Context;
  EFI_BLOCK_IO_MEDIA *Media = Disk->Io->Media;
  if (Media == NULL || !Media->MediaPresent) return EFI_NO_MEDIA;
  if (Media->MediaId != Disk->MediaId || Media->BlockSize != Disk->BlockSize ||
      Media->LastBlock != Disk->LastBlock) return EFI_MEDIA_CHANGED;
  if (Blocks == 0 || Lba > Media->LastBlock || Blocks - 1 > Media->LastBlock - Lba ||
      Blocks > MAX_UINTN / Media->BlockSize) return EFI_BAD_BUFFER_SIZE;
  return Disk->Io->ReadBlocks(Disk->Io, Disk->MediaId, Lba,
                              Blocks * Media->BlockSize, Buffer);
}

STATIC BOOLEAN UfsLunZero(CONST EFI_DEVICE_PATH_PROTOCOL *Path) {
  UINTN Total = 0;
  BOOLEAN Found = FALSE;
  if (Path == NULL) return FALSE;
  while (Total < 4096) {
    UINTN Size = (UINTN)Path->Length[0] | ((UINTN)Path->Length[1] << 8);
    if (Size < sizeof(*Path) || Size > 4096 - Total) return FALSE;
    if (Path->Type == END_DEVICE_PATH_TYPE)
      return (BOOLEAN)(Found && Path->SubType == END_ENTIRE_DEVICE_PATH_SUBTYPE && Size == 4);
    if (Path->Type == MEDIA_DEVICE_PATH) return FALSE; // Whole-LUN handles only.
    if (Path->Type == MESSAGING_DEVICE_PATH && Path->SubType == MSG_UFS_DP) {
      CONST UFS_DEVICE_PATH *Ufs = (CONST UFS_DEVICE_PATH *)Path;
      if (Found || Size != sizeof(*Ufs) || Ufs->Lun != 0 || Ufs->Pun != 0) return FALSE;
      Found = TRUE;
    }
    Total += Size;
    Path = (CONST EFI_DEVICE_PATH_PROTOCOL *)((CONST UINT8 *)Path + Size);
  }
  return FALSE;
}

STATIC VOID InspectPartition(CONST FDP_DISK *Disk, CONST FDP_PARTITION *Partition,
                              CONST CHAR16 *Name, VOID *Scratch) {
  EFI_STATUS Status;
  FDP_F2FS_GEOMETRY Geometry;
  UINT64 Blocks, Bytes;
  UINTN ReadBlocks;
  if (!Partition->Present) {
    Print(L"FUXIDATA %s: not found\n", Name);
    return;
  }
  Blocks = Partition->Last - Partition->First + 1;
  if (Blocks > MAX_UINT64 / Disk->BlockSize) {
    Print(L"FUXIDATA %s: geometry overflow\n", Name);
    return;
  }
  Bytes = Blocks * Disk->BlockSize;
  ReadBlocks = 4096 / Disk->BlockSize;
  Status = FdpReadPartition(Disk, Partition, 0, ReadBlocks, Scratch);
  if (!EFI_ERROR(Status)) Status = FdpInspectF2fs(Scratch, 4096, Bytes, &Geometry);
  Print(L"FUXIDATA %s LBA=%lx..%lx F2FS-header=%r\n",
        Name, Partition->First, Partition->Last, Status);
  if (!EFI_ERROR(Status)) {
    Print(L"  blocks=%lx root=%u cp=%u nat=%u; header only\n",
          Geometry.Blocks, Geometry.RootInode, Geometry.CheckpointBlock, Geometry.NatBlock);
  }
  // Inspect the independent second superblock too; never use it as a silent
  // fallback for mounting. No checkpoint/NAT/directory reads are issued here.
  Status = FdpReadPartition(Disk, Partition, ReadBlocks, ReadBlocks, Scratch);
  if (!EFI_ERROR(Status)) Status = FdpInspectF2fs(Scratch, 4096, Bytes, &Geometry);
  Print(L"FUXIDATA %s second-F2FS-header=%r\n", Name, Status);
}

STATIC VOID InspectDisks(VOID) {
  EFI_STATUS Status;
  EFI_HANDLE *Handles = NULL;
  UINTN Count = 0, I, Candidates = 0;
  EFI_BLOCK_IO_PROTOCOL *Selected = NULL;
  Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiBlockIoProtocolGuid, NULL, &Count, &Handles);
  if (EFI_ERROR(Status)) {
    Print(L"FUXIDATA BlockIo discovery=%r\n", Status);
    return;
  }
  // Resolve identity before reading. Multiple LUN0 candidates are ambiguous.
  for (I = 0; I < Count; ++I) {
    EFI_BLOCK_IO_PROTOCOL *Io = NULL;
    EFI_DEVICE_PATH_PROTOCOL *Path = NULL;
    Status = gBS->HandleProtocol(Handles[I], &gEfiBlockIoProtocolGuid, (VOID **)&Io);
    if (EFI_ERROR(Status) || Io == NULL || Io->Media == NULL ||
        Io->Media->LogicalPartition || Io->Media->RemovableMedia || !Io->Media->MediaPresent)
      continue;
    Status = gBS->HandleProtocol(Handles[I], &gEfiDevicePathProtocolGuid, (VOID **)&Path);
    if (EFI_ERROR(Status) || !UfsLunZero(Path)) continue;
    Selected = Io;
    ++Candidates;
  }
  FreePool(Handles);
  if (Candidates != 1) {
    Print(L"FUXIDATA UFS LUN0 candidates=%u; no disk reads\n", (UINT32)Candidates);
    Print(L"FUXIDATA native UFS takeover not implemented in M0\n");
    return;
  }
  {
    FDP_EFI_DISK Context;
    FDP_DISK Disk;
    FDP_PARTITIONS Partitions;
    UINTN Alignment, Pages = EFI_SIZE_TO_PAGES(FDP_SCRATCH_BYTES);
    VOID *Scratch;
    Context.Io = Selected;
    Context.MediaId = Selected->Media->MediaId;
    Context.BlockSize = Selected->Media->BlockSize;
    Context.LastBlock = Selected->Media->LastBlock;
    if (Context.BlockSize < 512 || Context.BlockSize > 4096 ||
        (Context.BlockSize & (Context.BlockSize - 1)) != 0) {
      Print(L"FUXIDATA unsupported BlockSize=%u\n", Context.BlockSize);
      return;
    }
    Alignment = Selected->Media->IoAlign;
    if (Alignment > 65536 || (Alignment > 1 && (Alignment & (Alignment - 1)) != 0)) {
      Print(L"FUXIDATA unsupported IoAlign=%u\n", (UINT32)Alignment);
      return;
    }
    if (Alignment < EFI_PAGE_SIZE) Alignment = EFI_PAGE_SIZE;
    Scratch = AllocateAlignedPages(Pages, Alignment);
    if (Scratch == NULL) {
      Print(L"FUXIDATA allocation failed\n");
      return;
    }
    Disk.Context = &Context;
    Disk.Read = ReadEfi;
    Disk.BlockSize = Context.BlockSize;
    Disk.LastBlock = Context.LastBlock;
    Status = FdpReadGpt(&Disk, Scratch, FDP_SCRATCH_BYTES, &Partitions);
    Print(L"FUXIDATA GPT=%r block-bytes=%u\n", Status, Disk.BlockSize);
    if (!EFI_ERROR(Status)) {
      InspectPartition(&Disk, &Partitions.Metadata, L"metadata", Scratch);
      InspectPartition(&Disk, &Partitions.Userdata, L"userdata", Scratch);
    }
    ZeroMem(Scratch, EFI_PAGES_TO_SIZE(Pages));
    FreeAlignedPages(Scratch, Pages);
  }
}

#if FUXI_DATA_SCM_QUERY
STATIC EFI_STATUS Availability(UINT32 Subject, BOOLEAN Smc64, BOOLEAN *Available) {
  UINT64 Values[8];
  ARM_SMC_ARGS Args;
  EFI_STATUS Status;
  Status = FdpMakeAvailabilityQuery(Subject, Smc64, Values);
  if (EFI_ERROR(Status)) return Status;
  ZeroMem(&Args, sizeof(Args));
  Args.Arg0 = (UINTN)Values[0];
  Args.Arg1 = (UINTN)Values[1];
  Args.Arg2 = (UINTN)Values[2];
  // INFO query only. No key operation, shared buffers, TA loading or RPMB call.
  ArmCallSmc(&Args);
  Status = FdpDecodeAvailability(Args.Arg0, Args.Arg1, Available);
  Print(L"FUXIDATA SCM query=%x abi=%u a0=%lx a1=%lx status=%r\n",
        Subject, Smc64 ? 64U : 32U, (UINT64)Args.Arg0, (UINT64)Args.Arg1, Status);
  return Status;
}
#endif

STATIC VOID InspectSecurity(VOID) {
  QCOM_SCM_PROTOCOL *Scm = NULL;
  QCOM_QSEECOM_PROTOCOL *Qsee = NULL;
  EFI_STATUS ScmStatus, QseeStatus;
  ScmStatus = gBS->LocateProtocol(&gQcomScmProtocolGuid, NULL, (VOID **)&Scm);
  QseeStatus = gBS->LocateProtocol(&gQcomQseecomProtocolGuid, NULL, (VOID **)&Qsee);
  Print(L"FUXIDATA protocols SCM=%r QSEE=%r (discovery only)\n", ScmStatus, QseeStatus);
#if FUXI_DATA_SCM_QUERY
  {
    BOOLEAN Available = FALSE;
    BOOLEAN Smc64 = TRUE;
    EFI_STATUS Status;
    UINTN I;
    CONST UINT32 Subjects[] = {FDP_SCM_ICE_SET, FDP_SCM_ICE_CLEAR, FDP_SCM_ICE_DERIVE};
    Status = Availability(FDP_SCM_INFO_AVAIL, TRUE, &Available);
    // Do not issue a second call after any interrupted/busy/error result.
    // An error is indeterminate, not proof that an ABI is unsupported.
    if (EFI_ERROR(Status)) return;
    if (!Available) {
      Smc64 = FALSE;
      Status = Availability(FDP_SCM_INFO_AVAIL, FALSE, &Available);
      if (EFI_ERROR(Status) || !Available) return;
    }
    for (I = 0; I < ARRAY_SIZE(Subjects); ++I) {
      Status = Availability(Subjects[I], Smc64, &Available);
      if (EFI_ERROR(Status)) return;
      Print(L"FUXIDATA SCM subject=%x available=%u; execution untested\n", Subjects[I], Available);
    }
  }
#else
  Print(L"FUXIDATA direct SMC queries disabled\n");
#endif
}

STATIC VOID EFIAPI ReadyToBoot(EFI_EVENT Event, VOID *Context) {
  (VOID)Context;
  if (mRan) return;
  mRan = TRUE;
  gBS->CloseEvent(Event);
  Print(L"\nFUXIDATA M0: read-only GPT/F2FS headers and security discovery\n");
  InspectSecurity();
  InspectDisks();
  Print(L"FUXIDATA END: data-decryption=UNIMPLEMENTED file-read=UNIMPLEMENTED\n");
  DEBUG((DEBUG_INFO, "FUXIDATA M0 completed; no decryptor or RAM publication\n"));
}

EFI_STATUS EFIAPI FuxiDataProbeDxeEntry(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
  (VOID)ImageHandle;
  (VOID)SystemTable;
  return gBS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, ReadyToBoot, NULL,
                            &gEfiEventReadyToBootGuid, &mReadyEvent);
}
