// SPDX-License-Identifier: BSD-2-Clause-Patent
// Read-only UFS command core. Freestanding: no MMIO, allocation, cache or
// clock calls of its own. Sequences mirror the proven NativeUfs transport.
#include "UfsCore.h"

STATIC UINT32 Be32(CONST UINT8 *P) {
  return ((UINT32)P[0] << 24) | ((UINT32)P[1] << 16) | ((UINT32)P[2] << 8) | (UINT32)P[3];
}
STATIC VOID PutBe32(UINT8 *P, UINT32 Value) {
  P[0] = (UINT8)(Value >> 24);
  P[1] = (UINT8)(Value >> 16);
  P[2] = (UINT8)(Value >> 8);
  P[3] = (UINT8)Value;
}
STATIC VOID SetZero(UINT8 *P, UINTN Bytes) {
  UINTN I;
  for (I = 0; I < Bytes; ++I) P[I] = 0;
}
STATIC VOID CopyBytes(VOID *Dst, CONST VOID *Src, UINTN Bytes) {
  UINT8 *D = Dst;
  CONST UINT8 *S = Src;
  UINTN I;
  for (I = 0; I < Bytes; ++I) D[I] = S[I];
}
STATIC INTN SameText(CONST CHAR8 *A, CONST CHAR8 *B) {
  UINTN I = 0;
  while (A[I] != 0 && A[I] == B[I]) ++I;
  return (INTN)(UINT8)A[I] - (INTN)(UINT8)B[I];
}

// Only reads CCAP and a bounded capability array; reject an overlapping or
// implausible configuration array before touching any capability entry.
EFI_STATUS FnuReadCryptoCapabilities(FNU_OPS *Ops, UINT32 Cap, UINT32 Hce,
                                     FNU_CRYPTO_CAP_REPORT *Report) {
  UINT32 Count, ConfigBase, End, I;
  if (Ops == NULL || Ops->Read == NULL || Report == NULL) return EFI_INVALID_PARAMETER;
  Report->Ccap = Report->EntryCount = Report->AdvertisedCount = 0;
  for (I = 0; I < FNU_CRYPTO_CAP_LIMIT; ++I) Report->Entries[I] = 0;
  if ((Cap & 0x10000000U) == 0 || (Hce & 1U) == 0) return EFI_UNSUPPORTED;
  Report->Ccap = Ops->Read(Ops, FNU_UFS_HC_BASE + 0x100U);
  if (Report->Ccap == 0xffffffffU) return EFI_DEVICE_ERROR;
  Count = Report->Ccap & 0xffU;
  Report->AdvertisedCount = Count;
  if (Count > FNU_CRYPTO_CAP_LIMIT) Count = FNU_CRYPTO_CAP_LIMIT;
  ConfigBase = (Report->Ccap >> 24) * 0x100U;
  End = 0x104U + Count * 4U;
  if (Count != 0 && ConfigBase < End)
    return EFI_COMPROMISED_DATA;
  for (I = 0; I < Count; ++I)
    Report->Entries[I] = Ops->Read(Ops, FNU_UFS_HC_BASE + 0x104U + 4U * I);
  Report->EntryCount = Count;
  return EFI_SUCCESS;
}

// The UFS key-size code 3 in an XTS entry corresponds to AES-256-XTS;
// SDUS bit 3 means a 4096-byte data unit (512 * 8). A capability is not a
// keyslot reservation or proof that the vendor's wrapped-key path is usable.
EFI_STATUS FnuFindXts4096Capability(CONST FNU_CRYPTO_CAP_REPORT *Report,
                                    UINT32 *Index) {
  UINT32 I, Entry;
  if (Report == NULL || Index == NULL) return EFI_INVALID_PARAMETER;
  *Index = MAX_UINT32;
  if (Report->EntryCount > FNU_CRYPTO_CAP_LIMIT ||
      Report->EntryCount > Report->AdvertisedCount) return EFI_COMPROMISED_DATA;
  for (I = 0; I < Report->EntryCount; ++I) {
    Entry = Report->Entries[I];
    if ((Entry & 0xffU) == 0 && ((Entry >> 16) & 0xffU) == 3 &&
        ((Entry >> 8) & 8U) != 0) { *Index = I; return EFI_SUCCESS; }
  }
  return EFI_NOT_FOUND;
}

// Command area: zero the 32-byte UTRD and the command/response/PRDT area.
VOID FnuClearCommandArea(UINT8 *Dma) {
  if (Dma == NULL) return;
  SetZero(Dma, 32);
  SetZero(Dma + FNU_UCD_OFFSET, FNU_PRDT_OFFSET + 16);
}

VOID FnuFillUtrd(UINT8 *Dma, UINT64 DmaPhys, UINT32 Direction, UINT32 DataBytes) {
  UINT32 *Words;
  UINT64 UcdPhys;
  if (Dma == NULL || Direction > FNU_DIR_READ) return;
  UcdPhys = DmaPhys + FNU_UCD_OFFSET;
  Words = (UINT32 *)(VOID *)Dma;
  Words[0] = 0x10000000U | (Direction << 25);
  Words[1] = 0;
  Words[2] = 0x0fU;  // OCS: not completed
  Words[3] = 0;
  Words[4] = (UINT32)UcdPhys;
  Words[5] = (UINT32)(UcdPhys >> 32);
  Words[6] = (512U >> 2) | ((FNU_RSP_OFFSET >> 2) << 16);
  Words[7] = (DataBytes ? 1U : 0U) | ((FNU_PRDT_OFFSET >> 2) << 16);
  if (DataBytes != 0) {
    // PRDT fields are little-endian native words (unlike the UPIU, which is
    // big-endian); a swapped data address faults the SMMU on the first
    // data-bearing command.
    UINT32 *Prd = (UINT32 *)(VOID *)(Dma + FNU_UCD_OFFSET + FNU_PRDT_OFFSET);
    UINT64 DataPhys = DmaPhys + FNU_DATA_OFFSET;
    Prd[0] = (UINT32)DataPhys;
    Prd[1] = (UINT32)(DataPhys >> 32);
    Prd[2] = 0;
    Prd[3] = DataBytes - 1;
  }
}

VOID FnuFillCommandUpiu(UINT8 *Dma, UINT8 Lun, UINT8 Flags, CONST UINT8 *Cdb,
                        UINTN CdbBytes, UINT32 DataBytes, UINT8 Tag) {
  UINT8 *Ucd;
  UINTN I;
  if (Dma == NULL || Cdb == NULL || CdbBytes == 0 || CdbBytes > 16) return;
  Ucd = Dma + FNU_UCD_OFFSET;
  Ucd[0] = 0x01;  // COMMAND UPIU
  Ucd[1] = Flags;
  Ucd[2] = Lun;
  Ucd[3] = Tag;
  PutBe32(Ucd + 12, DataBytes);
  for (I = 0; I < CdbBytes; ++I) Ucd[16 + I] = Cdb[I];
}

VOID FnuFillNopUpiu(UINT8 *Dma, UINT8 Tag) {
  UINT8 *Ucd;
  if (Dma == NULL) return;
  Ucd = Dma + FNU_UCD_OFFSET;
  Ucd[0] = 0x00;  // NOP OUT
  Ucd[3] = Tag;
}

VOID FnuFillQueryUpiu(UINT8 *Dma, UINT8 Opcode, UINT8 Idn, UINT8 Tag) {
  UINT8 *Ucd;
  if (Dma == NULL) return;
  Ucd = Dma + FNU_UCD_OFFSET;
  Ucd[0] = 0x16;  // QUERY REQUEST
  Ucd[3] = Tag;
  Ucd[5] = 0x01;  // standard read request
  Ucd[12] = Opcode;
  Ucd[13] = Idn;
}

BOOLEAN FnuBuildRead10(UINT8 Cdb[10], UINT64 Lba, UINTN Blocks) {
  if (Cdb == NULL || Blocks == 0 || Blocks > 0xffff ||
      Lba > (UINT64)MAX_UINT32 - (Blocks - 1)) {
    return FALSE;
  }
  SetZero(Cdb, 10);
  Cdb[0] = 0x28;  // READ(10)
  PutBe32(Cdb + 2, (UINT32)Lba);
  Cdb[7] = (UINT8)(Blocks >> 8);
  Cdb[8] = (UINT8)Blocks;
  return TRUE;
}

EFI_STATUS FnuValidateResponse(CONST UINT8 *Rsp, UINT8 Type, UINT8 Lun, UINT8 Tag,
                               UINT32 *ProtocolError) {
  UINTN Length;
  if (Rsp == NULL || ProtocolError == NULL) return EFI_INVALID_PARAMETER;
  *ProtocolError = 0;
  if (Rsp[0] != Type) *ProtocolError = 1;
  else if (Rsp[3] != Tag) *ProtocolError = 2;
  else if (Rsp[2] != Lun) *ProtocolError = 3;
  else {
    Length = ((UINTN)Rsp[10] << 8) | Rsp[11];
    if (Rsp[8] != 0 || Length > 512 - 32) *ProtocolError = 4;
  }
  if (*ProtocolError != 0) return EFI_PROTOCOL_ERROR;
  return EFI_SUCCESS;
}

VOID FnuParseScsi(CONST UINT8 *Rsp, UINT32 *ScsiStatus, UINT32 *Residual, UINT32 *Sense) {
  UINTN Length, SenseLength;
  CONST UINT8 *SenseData;
  *ScsiStatus = 0xffff;
  *Residual = 0;
  *Sense = 0;
  if (Rsp == NULL) return;
  *ScsiStatus = ((UINT32)Rsp[6] << 8) | Rsp[7];
  *Residual = Be32(Rsp + 12);
  Length = ((UINTN)Rsp[10] << 8) | Rsp[11];
  if (Length == 0) return;
  SenseLength = ((UINTN)Rsp[32] << 8) | Rsp[33];
  if (Length < 2 || SenseLength > Length - 2) return;
  SenseData = Rsp + 34;
  if (SenseLength >= 14 &&
      ((SenseData[0] & 0x7f) == 0x70 || (SenseData[0] & 0x7f) == 0x71)) {
    *Sense = ((UINT32)(SenseData[2] & 15) << 16) | ((UINT32)SenseData[12] << 8) | SenseData[13];
  } else if (SenseLength >= 4 &&
             ((SenseData[0] & 0x7f) == 0x72 || (SenseData[0] & 0x7f) == 0x73)) {
    *Sense = ((UINT32)(SenseData[1] & 15) << 16) | ((UINT32)SenseData[2] << 8) | SenseData[3];
  }
}

EFI_STATUS FnuParseQueryResponse(CONST UINT8 *Rsp, UINT8 Opcode, UINT8 Idn, UINT32 *Value) {
  if (Rsp == NULL || Value == NULL) return EFI_INVALID_PARAMETER;
  *Value = 0;
  if (Rsp[10] != 0 || Rsp[11] != 0) return EFI_PROTOCOL_ERROR;
  if (Rsp[12] != Opcode || Rsp[13] != Idn || Rsp[14] != 0 || Rsp[15] != 0) {
    return EFI_PROTOCOL_ERROR;
  }
  if (Rsp[6] != 0) return EFI_DEVICE_ERROR;
  *Value = Be32(Rsp + 20);
  return EFI_SUCCESS;
}

EFI_STATUS FnuParseNopResponse(CONST UINT8 *Rsp) {
  if (Rsp == NULL) return EFI_INVALID_PARAMETER;
  if (Rsp[10] != 0 || Rsp[11] != 0) return EFI_PROTOCOL_ERROR;
  if (Rsp[6] != 0 || Rsp[7] != 0) return EFI_PROTOCOL_ERROR;
  return EFI_SUCCESS;
}

CONST CHAR8 *FnuQueueStopPlan(UINT32 Hce, UINT32 Hcs, UINT32 Doorbell,
                              UINT32 TaskDoorbell, UINT32 Interrupt) {
  if ((Hce & 1) == 0 || (Hcs & 0x0f) != 0x0f) {
    return "controller not ready for takeover";
  }
  if (Doorbell != 0 || TaskDoorbell != 0) {
    return "firmware request outstanding";
  }
  if ((Interrupt & FNU_UFS_FATAL_STATUS) != 0) {
    return "firmware controller error";
  }
  return NULL;
}

BOOLEAN FnuWaitRegister(FNU_OPS *Ops, UINT64 Phys, UINT32 Mask, UINT32 Value, UINTN Attempts) {
  UINTN I;
  if (Ops == NULL || Ops->Read == NULL || Ops->Stall == NULL) return FALSE;
  for (I = 0; I < Attempts; ++I) {
    if ((Ops->Read(Ops, Phys) & Mask) == Value) return TRUE;
    Ops->Stall(Ops, 10);
  }
  return FALSE;
}

FNU_POLL_END FnuPollTransfer(FNU_DEVICE *Dev, FNU_OPS *Ops, UINTN MaxPolls,
                             FNU_POLL_STATE *State) {
  UINTN I;
  for (I = 0; ; ++I) {
    UINT32 Doorbell, Interrupt;
    ++State->Polls;
    Doorbell = Ops->Read(Ops, Dev->HcPhys + FNU_REG_UTRLDBR);
    State->DoorbellSeen |= Doorbell;
    Interrupt = Ops->Read(Ops, Dev->HcPhys + FNU_REG_IS);
    State->InterruptSeen |= Interrupt;
    if ((State->InterruptSeen & FNU_UFS_FATAL_STATUS) != 0) return FNU_POLL_FATAL;
    if ((Doorbell & 1) == 0) {
      // A zero doorbell alone does not prove that this command was accepted;
      // also allow a completion so fast that software never observes DB=1.
      Ops->CacheInvalidate(Ops, Dev->Dma, 64);
      State->Ocs = *(volatile UINT32 *)(VOID *)(Dev->Dma + 8) & 0xff;
      if (State->Ocs != 0x0f) return FNU_POLL_COMPLETED;
    }
    if (I + 1 >= MaxPolls) return FNU_POLL_TIMEOUT;
    Ops->Stall(Ops, 2);
  }
}

// Check-before-touch clear of the command/response/PRDT area (hostClearUcd).
STATIC BOOLEAN FnuClearUcd(FNU_DEVICE *Dev, FNU_OPS *Ops) {
  if (*Dev->Poisoned) return FALSE;
  if (Ops->Read(Ops, Dev->HcPhys + FNU_REG_UTRLDBR) != 0) {
    *Dev->Poisoned = TRUE;
    return FALSE;
  }
  if ((Ops->Read(Ops, Dev->HcPhys + FNU_REG_IS) & FNU_UFS_FATAL_STATUS) != 0) {
    *Dev->Poisoned = TRUE;
    return FALSE;
  }
  SetZero(Dev->Dma + FNU_UCD_OFFSET, FNU_PRDT_OFFSET + 16);
  return TRUE;
}

EFI_STATUS FnuSubmit(FNU_DEVICE *Dev, FNU_OPS *Ops, UINT32 Direction, UINT32 DataBytes,
                     UINTN MaxPolls, UINT32 *Ocs) {
  FNU_POLL_STATE State;
  FNU_POLL_END End;
  UINT32 CommandOcs;
  if (Ocs == NULL) return EFI_INVALID_PARAMETER;
  *Ocs = 0x0f;
  if (Dev == NULL || Ops == NULL || Dev->Dma == NULL || Dev->Poisoned == NULL ||
      MaxPolls == 0 || DataBytes > FNU_DATA_MAX || (DataBytes & 3) != 0 ||
      (DataBytes != 0 ? Direction != FNU_DIR_READ : Direction != FNU_DIR_NONE)) {
    return EFI_INVALID_PARAMETER;
  }
  if (*Dev->Poisoned) return EFI_NOT_READY;
  if (Ops->Read(Ops, Dev->HcPhys + FNU_REG_UTRLDBR) != 0) {
    *Dev->Poisoned = TRUE;
    return EFI_NOT_READY;
  }
  if ((Ops->Read(Ops, Dev->HcPhys + FNU_REG_IS) & FNU_UFS_FATAL_STATUS) != 0) {
    *Dev->Poisoned = TRUE;
    return EFI_DEVICE_ERROR;
  }
  FnuFillUtrd(Dev->Dma, Dev->DmaPhys, Direction, DataBytes);
  Ops->CacheCleanInvalidate(Ops, Dev->Dma, FNU_DATA_OFFSET + DataBytes);
  // Acknowledge completion only; preserve error evidence.
  Ops->Write(Ops, Dev->HcPhys + FNU_REG_IS, 1);
  Ops->Write(Ops, Dev->HcPhys + FNU_REG_UTRLDBR, 1);
  SetZero((UINT8 *)&State, sizeof(State));
  State.Ocs = 0x0f;
  End = FnuPollTransfer(Dev, Ops, MaxPolls, &State);
  *Ocs = State.Ocs;
  if (End != FNU_POLL_COMPLETED) {
    // No cancel/reset/retry: the controller may still own the buffer even
    // with DB=0. Keep it allocated and prohibit all subsequent CPU writes.
    *Dev->Poisoned = TRUE;
    return End == FNU_POLL_TIMEOUT ? EFI_TIMEOUT : EFI_DEVICE_ERROR;
  }
  Ops->CacheInvalidate(Ops, Dev->Dma, FNU_DATA_OFFSET + DataBytes);
  CommandOcs = *(volatile UINT32 *)(VOID *)(Dev->Dma + 8) & 0xff;
  return CommandOcs == 0 ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}

STATIC EFI_STATUS FnuScsiRun(FNU_DEVICE *Dev, FNU_OPS *Ops, UINT8 Lun, UINT8 Flags,
                             CONST UINT8 *Cdb, UINTN CdbBytes, UINT32 DataBytes,
                             UINTN MaxPolls, UINT32 *ScsiStatus, UINT32 *Sense,
                             UINT32 *Residual, UINT32 *ProtocolError) {
  UINT32 Ocs = 0xf;
  EFI_STATUS Status;
  UINT8 *Rsp;
  if (Dev == NULL || Dev->Dma == NULL || Dev->Poisoned == NULL || Ops == NULL ||
      Cdb == NULL || CdbBytes == 0 || CdbBytes > 16 || ProtocolError == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *ScsiStatus = 0xffff;
  *Sense = 0;
  *Residual = 0;
  *ProtocolError = 0;
  if (*Dev->Poisoned) return EFI_NOT_READY;
  if (!FnuClearUcd(Dev, Ops)) return EFI_NOT_READY;
  FnuFillCommandUpiu(Dev->Dma, Lun, Flags, Cdb, CdbBytes, DataBytes, 0);
  Status = FnuSubmit(Dev, Ops, DataBytes != 0 ? FNU_DIR_READ : FNU_DIR_NONE,
                     DataBytes, MaxPolls, &Ocs);
  if (EFI_ERROR(Status)) return Status;
  Rsp = Dev->Dma + FNU_UCD_OFFSET + FNU_RSP_OFFSET;
  Status = FnuValidateResponse(Rsp, 0x21, Lun, 0, ProtocolError);
  if (EFI_ERROR(Status)) return Status;
  FnuParseScsi(Rsp, ScsiStatus, Residual, Sense);
  if (*ScsiStatus == 0 && ((Rsp[1] & 0x60) != 0 || *Residual != 0)) {
    *ProtocolError = 6;  // short/overrun transfer
    return EFI_PROTOCOL_ERROR;
  }
  return *ScsiStatus == 0 ? EFI_SUCCESS : EFI_NOT_READY;
}

EFI_STATUS FnuTestUnitReady(FNU_DEVICE *Dev, FNU_OPS *Ops, UINTN MaxPolls) {
  STATIC CONST UINT8 Tur[6] = {0x00, 0, 0, 0, 0, 0};
  UINT32 Scsi, Sense, Residual, Protocol;
  return FnuScsiRun(Dev, Ops, 0, 0x00, Tur, sizeof(Tur), 0, MaxPolls,
                    &Scsi, &Sense, &Residual, &Protocol);
}

EFI_STATUS FnuStartStopUnit(FNU_DEVICE *Dev, FNU_OPS *Ops, UINTN MaxPolls) {
  STATIC CONST UINT8 Ssu[6] = {0x1b, 0, 0, 0, 0x10, 0};  // power condition ACTIVE
  UINT32 Scsi, Sense, Residual, Protocol;
  // Device well-known LU only; no user LUN and no power-down condition.
  return FnuScsiRun(Dev, Ops, 0xd0, 0x00, Ssu, sizeof(Ssu), 0, MaxPolls,
                    &Scsi, &Sense, &Residual, &Protocol);
}

EFI_STATUS FnuReadCapacity(FNU_DEVICE *Dev, FNU_OPS *Ops, UINT32 *LastLba,
                           UINT32 *BlockBytes, UINTN MaxPolls) {
  STATIC CONST UINT8 Cdb[10] = {0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  UINT32 Scsi, Sense, Residual, Protocol;
  EFI_STATUS Status;
  CONST UINT8 *Data;
  if (Dev == NULL || Dev->Dma == NULL || LastLba == NULL || BlockBytes == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *LastLba = 0;
  *BlockBytes = 0;
  Status = FnuScsiRun(Dev, Ops, 0, 0x40, Cdb, sizeof(Cdb), 8, MaxPolls,
                      &Scsi, &Sense, &Residual, &Protocol);
  if (EFI_ERROR(Status)) return Status;
  Data = (CONST UINT8 *)Dev->Dma + FNU_DATA_OFFSET;
  *LastLba = Be32(Data);
  *BlockBytes = Be32(Data + 4);
  return EFI_SUCCESS;
}

EFI_STATUS FnuReadBlocks(FNU_DEVICE *Dev, FNU_OPS *Ops, UINT64 Lba, UINTN Blocks,
                         VOID *Dst, UINTN MaxPolls) {
  UINT8 Cdb[10];
  UINT32 Scsi, Sense, Residual, Protocol;
  EFI_STATUS Status;
  if (Dev == NULL || Dev->Dma == NULL || Dst == NULL || Blocks == 0 ||
      Blocks > FNU_DATA_LBAS) {
    return EFI_INVALID_PARAMETER;
  }
  if (!FnuBuildRead10(Cdb, Lba, Blocks)) return EFI_INVALID_PARAMETER;
  Status = FnuScsiRun(Dev, Ops, 0, 0x40, Cdb, sizeof(Cdb), (UINT32)(Blocks * 4096U),
                      MaxPolls, &Scsi, &Sense, &Residual, &Protocol);
  if (EFI_ERROR(Status)) return Status;
  CopyBytes(Dst, Dev->Dma + FNU_DATA_OFFSET, Blocks * 4096U);
  return EFI_SUCCESS;
}

EFI_STATUS FnuNop(FNU_DEVICE *Dev, FNU_OPS *Ops, UINTN MaxPolls) {
  UINT32 Ocs, Protocol;
  EFI_STATUS Status;
  UINT8 *Rsp;
  if (Dev == NULL || Dev->Dma == NULL || Dev->Poisoned == NULL || Ops == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  if (*Dev->Poisoned) return EFI_NOT_READY;
  if (!FnuClearUcd(Dev, Ops)) return EFI_NOT_READY;
  FnuFillNopUpiu(Dev->Dma, 1);
  Status = FnuSubmit(Dev, Ops, FNU_DIR_NONE, 0, MaxPolls, &Ocs);
  if (EFI_ERROR(Status)) return Status;
  Rsp = Dev->Dma + FNU_UCD_OFFSET + FNU_RSP_OFFSET;
  Status = FnuValidateResponse(Rsp, 0x20, 0, 1, &Protocol);
  if (EFI_ERROR(Status)) return Status;
  return FnuParseNopResponse(Rsp);
}

EFI_STATUS FnuQueryRead(FNU_DEVICE *Dev, FNU_OPS *Ops, UINT8 Opcode, UINT8 Idn,
                        UINT32 *Value, UINTN MaxPolls) {
  UINT32 Ocs, Protocol;
  EFI_STATUS Status;
  UINT8 *Rsp;
  if (Value == NULL) return EFI_INVALID_PARAMETER;
  *Value = 0;
  if (Opcode != 0x03 && Opcode != 0x05) return EFI_ACCESS_DENIED;
  if (Dev == NULL || Dev->Dma == NULL || Dev->Poisoned == NULL || Ops == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  if (*Dev->Poisoned) return EFI_NOT_READY;
  if (!FnuClearUcd(Dev, Ops)) return EFI_NOT_READY;
  FnuFillQueryUpiu(Dev->Dma, Opcode, Idn, 1);
  Status = FnuSubmit(Dev, Ops, FNU_DIR_NONE, 0, MaxPolls, &Ocs);
  if (EFI_ERROR(Status)) return Status;
  Rsp = Dev->Dma + FNU_UCD_OFFSET + FNU_RSP_OFFSET;
  Status = FnuValidateResponse(Rsp, 0x36, 0, 1, &Protocol);
  if (EFI_ERROR(Status)) return Status;
  return FnuParseQueryResponse(Rsp, Opcode, Idn, Value);
}

// ---- ARM SMMUv2 planning and configuration (SmmuTakeover.h port) ------------

STATIC UINT32 FnuSmmuAddressBits(UINT32 Code) {
  switch (Code) {
    case 0: return 32;
    case 1: return 36;
    case 2: return 40;
    case 3: return 42;
    case 4: return 44;
    case 5: return 48;
    default: return 0;
  }
}

FNU_SMMU_PLAN FnuPlanSmmuBank(UINT16 Stream, UINT64 Dma, UINT64 Bytes, VOID *Context,
                              FNU_SMMU_READ Read, UINTN BankFromTop) {
  FNU_SMMU_PLAN P;
  UINT32 Idr0, Idr1, Idr2, Count, Banks;
  UINTN Shift, I;
  SetZero((UINT8 *)&P, sizeof(P));
  P.Slot = 0xffffffffU;
  if (Read == NULL) {
    P.Error = "SMMU read callback";
    return P;
  }
  Idr0 = Read(Context, 0x20);
  Idr2 = Read(Context, 0x28);
  Count = Idr0 & 255;
  if ((Idr0 & (1U << 30)) == 0 || (Idr2 & (1U << 12)) == 0) {
    P.Error = "SMMU AArch64 stage 1 unsupported";
    return P;
  }
  for (Shift = 0; Shift <= 8; Shift += 4) {
    UINT32 Bits = FnuSmmuAddressBits((Idr2 >> Shift) & 15);
    if (Bits == 0 || Bytes == 0 || Dma >= (1ULL << Bits) || Bytes > (1ULL << Bits) - Dma) {
      P.Error = "DMA exceeds SMMU address width";
      return P;
    }
  }
  Idr1 = Read(Context, 0x24);
  Banks = Idr1 & 255;
  P.Pages = 1U << (((Idr1 >> 28) & 7) + 1);
  if ((Idr1 & (1U << 31)) != 0 || Count == 0 || P.Pages > 128 ||
      Banks < 2 || Banks > 128 || (P.Pages + Banks) * 4096 > 0xd0000) {
    P.Error = "unsupported SMMU geometry";
    return P;
  }
  if (BankFromTop >= Banks - 1) {
    P.Error = "no free context bank";
    return P;
  }
  P.Bank = Banks - 1 - BankFromTop;
  if (Count > 128) Count = 128;  // Firmware's reliably accessible groups only.
  {
    UINTN Matches = 0;
    for (I = 0; I < Count; ++I) {
      UINT32 Smr = Read(Context, 0x800 + 4 * I);
      if ((Smr & 0x80000000U) == 0) {
        if (!P.Reuse) P.Slot = (UINT32)I;
        continue;
      }
      {
        UINT32 S2Cr = Read(Context, 0xc00 + 4 * I);
        UINT32 Mask = (Smr >> 16) & 0x7fff;
        BOOLEAN Match = (((Smr ^ Stream) & 0xffff & ~Mask) == 0);
        BOOLEAN OurBank = ((S2Cr >> 16) & 3) == 0 && (S2Cr & 255) == P.Bank;
        if (Match) {
          ++Matches;
          if (Matches > 1 || Mask != 0 || !OurBank) {
            P.Slot = (UINT32)I;
            P.Smr = Smr;
            P.S2Cr = S2Cr;
            P.Error = "conflicting UFS stream mapping";
            return P;
          }
          P.Reuse = TRUE;
          P.Slot = (UINT32)I;
        } else if (OurBank) {
          P.Slot = (UINT32)I;
          P.Smr = Smr;
          P.S2Cr = S2Cr;
          P.Error = "reserved context bank already used";
          return P;
        }
      }
    }
  }
  {
    UINT32 Sctlr = Read(Context, (P.Pages + P.Bank) * 4096);
    if ((Sctlr & 1) != 0 ||
        (P.Reuse && (Sctlr != 0 || Read(Context, 0x1000 + 4 * P.Bank) != 0x10000 ||
                     (Read(Context, 0x1800 + 4 * P.Bank) & ~1U) != 0))) {
      P.Error = "reserved context bank not bypass";
      return P;
    }
  }
  if (P.Slot == 0xffffffffU) P.Error = "no free stream-match group";
  return P;
}

STATIC BOOLEAN FnuSmmuRetryable(CONST CHAR8 *Error) {
  return Error != NULL &&
         (SameText(Error, "reserved context bank already used") == 0 ||
          SameText(Error, "reserved context bank not bypass") == 0 ||
          SameText(Error, "conflicting UFS stream mapping") == 0);
}

FNU_SMMU_PLAN FnuPlanSmmu(UINT16 Stream, UINT64 Dma, UINT64 Bytes, VOID *Context,
                          FNU_SMMU_READ Read) {
  return FnuPlanSmmuFrom(Stream, Dma, Bytes, Context, Read, 0);
}

FNU_SMMU_PLAN FnuPlanSmmuFrom(UINT16 Stream, UINT64 Dma, UINT64 Bytes, VOID *Context,
                              FNU_SMMU_READ Read, UINTN BankFromTop) {
  FNU_SMMU_PLAN First;
  UINTN Attempt;
  First = FnuPlanSmmuBank(Stream, Dma, Bytes, Context, Read, BankFromTop);
  if (First.Error == NULL) return First;
  // "Conflicting" is retried too: our own stream may already sit on a lower
  // bank from an earlier run that had to fall back.
  if (!FnuSmmuRetryable(First.Error)) return First;
  for (Attempt = BankFromTop + 1; Attempt < 8; ++Attempt) {
    FNU_SMMU_PLAN Next = FnuPlanSmmuBank(Stream, Dma, Bytes, Context, Read, Attempt);
    if (Next.Error == NULL) return Next;
    if (!FnuSmmuRetryable(Next.Error)) break;
  }
  return First;
}

CONST CHAR8 *FnuConfigureSmmu(CONST FNU_SMMU_PLAN *Plan, UINT16 Stream, VOID *Context,
                              FNU_SMMU_READ Read, FNU_SMMU_WRITE Write) {
  UINTN Cb;
  if (Plan == NULL || Read == NULL || Write == NULL) return "SMMU callback";
  if (Plan->Error != NULL) return Plan->Error;
  Cb = (Plan->Pages + Plan->Bank) * 4096;
  if (!Plan->Reuse) {
    Write(Context, Cb, 0);
    if (Read(Context, Cb) != 0) return "SMMU bypass disable readback";
  }
  // Set VA64 before exposing a newly allocated stream. Repair an exclusive
  // existing 32-bit bypass too; do not silently reuse the faulty state.
  if (Read(Context, 0x1800 + 4 * Plan->Bank) != 1) Write(Context, 0x1800 + 4 * Plan->Bank, 1);
  if (!Plan->Reuse) Write(Context, 0x1000 + 4 * Plan->Bank, 0x10000);
  if (Read(Context, 0x1800 + 4 * Plan->Bank) != 1 ||
      Read(Context, 0x1000 + 4 * Plan->Bank) != 0x10000 ||
      Read(Context, Cb) != 0) {
    return "SMMU VA64 bypass readback";
  }
  if (!Plan->Reuse) {
    Write(Context, 0xc00 + 4 * Plan->Slot, Plan->Bank);
    if (Read(Context, 0xc00 + 4 * Plan->Slot) != Plan->Bank) {
      return "SMMU stream context readback";
    }
    Write(Context, 0x800 + 4 * Plan->Slot, 0x80000000U | Stream);
  }
  if (Read(Context, 0x800 + 4 * Plan->Slot) != (0x80000000U | Stream) ||
      Read(Context, 0xc00 + 4 * Plan->Slot) != Plan->Bank) {
    return "SMMU stream mapping readback";
  }
  return NULL;
}
