// SPDX-License-Identifier: BSD-2-Clause-Patent
// Exercise the actual freestanding UFS command core against a modeled host
// controller, and the SMMU planner against modeled register files. No MMIO,
// cache or clock work happens here: the ops callbacks are fake registers.
#include "UfsCore.h"
#include "UfsSha256.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HC_BASE 0x01d84000ULL
#define SMMU_BASE 0x15000000ULL

typedef struct {
  UINT32 Reg[0x100];  // word-indexed by offset/4; used offsets are <= 0x78
  UINT8 *Dma;
  UINT64 DmaPhys;
  UINTN Rings;
  int StickDoorbell;     // device never completes
  int InjectFatalOnRing; // fatal interrupt appears at completion time
  UINT32 OcsToReport;    // OCS the device writes; 0xf means none (stays preset)
  UINT32 ScsiStatus;     // SCSI status byte for command responses
  UINT32 QueryValue;     // value field for query responses
  UINT32 CapLastLba;     // READ CAPACITY payload
  UINT32 CapBlockBytes;
  int WithSense;         // CHECK CONDITION with fixed sense data
  int ExpectCommand;     // 0 none, 1 command UPIU, 2 query, 3 nop
  UINT8 ExpectLun;
  UINT8 ExpectCdb0;
  UINT32 ExpectDataBytes;
  UINTN Failures;
  UINTN CivCalls, InvCalls, StallCalls;
} HC;

static void Fail(HC *Hc, const char *Why) {
  fprintf(stderr, "fake device: %s\n", Why);
  Hc->Failures++;
}

static void PutBe32(UINT8 *At, UINT32 Value) {
  At[0] = (UINT8)(Value >> 24);
  At[1] = (UINT8)(Value >> 16);
  At[2] = (UINT8)(Value >> 8);
  At[3] = (UINT8)Value;
}

static UINT32 GetBe32(const UINT8 *At) {
  return ((UINT32)At[0] << 24) | ((UINT32)At[1] << 16) | ((UINT32)At[2] << 8) | At[3];
}

static UINT32 HcRead(FNU_OPS *Ops, UINT64 Phys) {
  HC *Hc = Ops->Context;
  assert(Phys >= HC_BASE && Phys < HC_BASE + 0x3000 && ((Phys & 3) == 0));
  return Hc->Reg[(UINTN)(Phys - HC_BASE) / 4];
}

static UINT8 ResponseType(UINT8 RequestType) {
  if (RequestType == 0x01) return 0x21;
  if (RequestType == 0x00) return 0x20;
  if (RequestType == 0x16) return 0x36;
  return 0xff;
}

// Simulate the device completing the command in the window.
static void Complete(HC *Hc) {
  UINT8 *Ucd = Hc->Dma + FNU_UCD_OFFSET;
  UINT8 Type = ResponseType(Ucd[0]);
  if (Type == 0xff) {
    Fail(Hc, "unknown request UPIU type");
    return;
  }
  Hc->Reg[FNU_REG_UTRLDBR / 4] = 0;
  if (Hc->InjectFatalOnRing) Hc->Reg[FNU_REG_IS / 4] |= FNU_UFS_FATAL_STATUS;
  if (Hc->OcsToReport == 0xf) return;  // no completion write; OCS stays 0xf
  *(volatile UINT32 *)(VOID *)(Hc->Dma + 8) = Hc->OcsToReport;
  if (Hc->OcsToReport != 0) return;
  memset(Ucd + FNU_RSP_OFFSET, 0, 64);
  Ucd[FNU_RSP_OFFSET + 0] = Type;
  Ucd[FNU_RSP_OFFSET + 2] = Hc->ExpectLun;
  Ucd[FNU_RSP_OFFSET + 3] = Ucd[3];  // echo the task tag
  if (Hc->WithSense) {
    // CHECK CONDITION, fixed sense: NOT READY, ASC 0x04, ASCQ 0x01.
    Ucd[FNU_RSP_OFFSET + 6] = 0;
    Ucd[FNU_RSP_OFFSET + 7] = 2;
    Ucd[FNU_RSP_OFFSET + 10] = 0;
    Ucd[FNU_RSP_OFFSET + 11] = 18;
    Ucd[FNU_RSP_OFFSET + 32] = 0;
    Ucd[FNU_RSP_OFFSET + 33] = 14;
    Ucd[FNU_RSP_OFFSET + 34] = 0x70;
    Ucd[FNU_RSP_OFFSET + 36] = 0x02;
    Ucd[FNU_RSP_OFFSET + 46] = 0x04;
    Ucd[FNU_RSP_OFFSET + 47] = 0x01;
    return;
  }
  Ucd[FNU_RSP_OFFSET + 7] = (UINT8)Hc->ScsiStatus;
  if (Type == 0x36) {
    Ucd[FNU_RSP_OFFSET + 12] = Ucd[12];  // echo the queried opcode
    Ucd[FNU_RSP_OFFSET + 13] = Ucd[13];  // echo the queried idn
    PutBe32(Ucd + FNU_RSP_OFFSET + 20, Hc->QueryValue);
  } else if (Type == 0x21 && Hc->ExpectDataBytes != 0) {
    // PRDT transfers carry no in-segment data; the response segment length
    // stays zero.
    for (UINTN I = 0; I < Hc->ExpectDataBytes; ++I) {
      Hc->Dma[FNU_DATA_OFFSET + I] = (UINT8)(I * 7 + 3);
    }
    if (Ucd[16] == 0x25) {  // READ CAPACITY(10)
      PutBe32(Hc->Dma + FNU_DATA_OFFSET, Hc->CapLastLba);
      PutBe32(Hc->Dma + FNU_DATA_OFFSET + 4, Hc->CapBlockBytes);
    }
  }
}

static void ValidateRequest(HC *Hc) {
  const UINT32 *Words = (const UINT32 *)(const VOID *)Hc->Dma;
  const UINT8 *Ucd = Hc->Dma + FNU_UCD_OFFSET;
  UINT64 UcdPhys = (UINT64)Words[5] << 32 | Words[4];
  UINT32 Direction = (Words[0] >> 25) & 3;
  if (UcdPhys != Hc->DmaPhys + FNU_UCD_OFFSET) Fail(Hc, "UTRD command UPIU address");
  if ((Words[6] & 0xffff) != (512 / 4) || (Words[6] >> 16) != (FNU_RSP_OFFSET / 4)) {
    Fail(Hc, "UTRD response length/offset");
  }
  if (Hc->ExpectDataBytes != 0) {
    UINT64 DataPhys = (UINT64)GetBe32(Hc->Dma + FNU_UCD_OFFSET + FNU_PRDT_OFFSET + 4) << 32 |
                      GetBe32(Hc->Dma + FNU_UCD_OFFSET + FNU_PRDT_OFFSET);
    if ((Words[7] & 0xffff) != 1) Fail(Hc, "PRDT entry count");
    if (DataPhys != Hc->DmaPhys + FNU_DATA_OFFSET) Fail(Hc, "PRDT data address");
    if (GetBe32(Hc->Dma + FNU_UCD_OFFSET + FNU_PRDT_OFFSET + 12) != Hc->ExpectDataBytes - 1) {
      Fail(Hc, "PRDT byte count");
    }
    if (GetBe32(Ucd + 12) != Hc->ExpectDataBytes) Fail(Hc, "UPIU expected transfer length");
    if (Direction != FNU_DIR_READ) Fail(Hc, "data command direction");
    if ((Ucd[1] & 0x40) == 0) Fail(Hc, "UPIU read flag");
  } else if (Direction != FNU_DIR_NONE) {
    Fail(Hc, "no-data command direction");
  }
  if (Hc->ExpectCommand != 0 && Ucd[0] != 0x01 && Ucd[0] != 0x16 && Ucd[0] != 0x00) {
    Fail(Hc, "UPIU type");
  }
  if (Hc->ExpectCommand == 1 && (Ucd[0] != 0x01 || Ucd[16] != Hc->ExpectCdb0)) {
    Fail(Hc, "command UPIU/CDB opcode");
  }
  if (Hc->ExpectCommand == 2 && (Ucd[0] != 0x16 || Ucd[3] != 1 || Ucd[5] != 1)) {
    Fail(Hc, "query UPIU shape");
  }
  if (Hc->ExpectCommand == 3 && (Ucd[0] != 0x00 || Ucd[3] != 1)) {
    Fail(Hc, "NOP UPIU shape");
  }
  if (Ucd[2] != Hc->ExpectLun) Fail(Hc, "UPIU LUN");
}

static void HcWrite(FNU_OPS *Ops, UINT64 Phys, UINT32 Value) {
  HC *Hc = Ops->Context;
  UINTN Index = (UINTN)(Phys - HC_BASE) / 4;
  assert(Phys >= HC_BASE && Phys < HC_BASE + 0x3000 && ((Phys & 3) == 0));
  if (Index == FNU_REG_IS / 4) {
    Hc->Reg[Index] &= ~Value;  // write-1-to-clear
    return;
  }
  Hc->Reg[Index] = Value;
  if (Index == FNU_REG_UTRLDBR / 4 && (Value & 1) != 0) {
    Hc->Rings++;
    ValidateRequest(Hc);
    if (!Hc->StickDoorbell) Complete(Hc);
  }
}

static VOID FnuStallFake(FNU_OPS *Ops, UINTN Microseconds) {
  (VOID)Microseconds;
  ((HC *)Ops->Context)->StallCalls++;
}

static VOID FnuCiv(FNU_OPS *Ops, VOID *Va, UINTN Bytes) {
  (VOID)Va;
  (VOID)Bytes;
  ((HC *)Ops->Context)->CivCalls++;
}

static VOID FnuInv(FNU_OPS *Ops, VOID *Va, UINTN Bytes) {
  (VOID)Va;
  (VOID)Bytes;
  ((HC *)Ops->Context)->InvCalls++;
}

static void ResetHc(HC *Hc, UINT8 *Dma, UINT64 DmaPhys) {
  memset(Hc, 0, sizeof(*Hc));
  Hc->Dma = Dma;
  Hc->DmaPhys = DmaPhys;
  Hc->Reg[FNU_REG_HCE / 4] = 1;
  Hc->Reg[FNU_REG_HCS / 4] = 0x0f;
}

static void ExpectStatus(const char *Label, EFI_STATUS Got, EFI_STATUS Want) {
  if (Got != Want) {
    fprintf(stderr, "%s: got %llx want %llx\n", Label, (unsigned long long)Got,
            (unsigned long long)Want);
    exit(1);
  }
}

static void CommandScenarios(UINT8 *Dma, UINT64 DmaPhys) {
  FNU_OPS Ops = {0};
  FNU_DEVICE Dev = {0};
  HC Hc;
  BOOLEAN Poisoned = FALSE;
  UINT32 Value;
  UINT32 LastLba, BlockBytes;
  UINT8 Buffer[2 * 4096];
  EFI_STATUS Status;

  Ops.Context = &Hc;
  Ops.Read = HcRead;
  Ops.Write = HcWrite;
  Ops.Stall = FnuStallFake;
  Ops.CacheCleanInvalidate = FnuCiv;
  Ops.CacheInvalidate = FnuInv;
  Dev.HcPhys = HC_BASE;
  Dev.Dma = Dma;
  Dev.DmaPhys = DmaPhys;
  Dev.Poisoned = &Poisoned;

  ResetHc(&Hc, Dma, DmaPhys);
  Hc.ExpectCommand = 3;
  Status = FnuNop(&Dev, &Ops, 1000);
  ExpectStatus("nop", Status, EFI_SUCCESS);
  assert(Hc.Rings == 1 && Hc.Failures == 0);

  ResetHc(&Hc, Dma, DmaPhys);
  Hc.ExpectCommand = 2;
  Hc.QueryValue = 0x33;
  Status = FnuQueryRead(&Dev, &Ops, 0x03, 0x02, &Value, 1000);
  ExpectStatus("power query", Status, EFI_SUCCESS);
  assert(Value == 0x33 && Hc.Failures == 0);
  assert(FnuQueryRead(&Dev, &Ops, 0x06, 0x00, &Value, 1000) == EFI_ACCESS_DENIED);

  ResetHc(&Hc, Dma, DmaPhys);
  Hc.ExpectCommand = 1;
  Hc.ExpectLun = 0xd0;
  Hc.ExpectCdb0 = 0x1b;
  Status = FnuStartStopUnit(&Dev, &Ops, 1000);
  ExpectStatus("ssu", Status, EFI_SUCCESS);

  ResetHc(&Hc, Dma, DmaPhys);
  Hc.ExpectCommand = 1;
  Status = FnuTestUnitReady(&Dev, &Ops, 1000);
  ExpectStatus("tur", Status, EFI_SUCCESS);

  ResetHc(&Hc, Dma, DmaPhys);
  Hc.ExpectCommand = 1;
  Hc.ExpectCdb0 = 0x25;
  Hc.ExpectDataBytes = 8;
  Hc.ScsiStatus = 0;
  Hc.CapLastLba = 0x03afc3fa;
  Hc.CapBlockBytes = 4096;
  Status = FnuReadCapacity(&Dev, &Ops, &LastLba, &BlockBytes, 1000);
  ExpectStatus("capacity", Status, EFI_SUCCESS);
  assert(LastLba == 0x03afc3fa && BlockBytes == 4096);

  ResetHc(&Hc, Dma, DmaPhys);
  Hc.ExpectCommand = 1;
  Hc.ExpectCdb0 = 0x28;
  Hc.ExpectDataBytes = 2 * 4096;
  Status = FnuReadBlocks(&Dev, &Ops, 0x2f7840, 2, Buffer, 1000);
  ExpectStatus("read10", Status, EFI_SUCCESS);
  assert(Buffer[0] == 3 && Buffer[1] == 10 && Buffer[4096] == (UINT8)(4096 * 7 + 3));
  assert(FnuReadBlocks(&Dev, &Ops, 0, FNU_DATA_LBAS + 1, Buffer, 1000) == EFI_INVALID_PARAMETER);
  assert(FnuReadBlocks(&Dev, &Ops, (UINT64)MAX_UINT32, 2, Buffer, 1000) == EFI_INVALID_PARAMETER);
  {
    UINT8 Cdb[10];
    assert(!FnuBuildRead10(Cdb, (UINT64)MAX_UINT32, 2));
    assert(FnuBuildRead10(Cdb, (UINT64)MAX_UINT32 - 1, 2));  // last valid pair
    assert(FnuBuildRead10(Cdb, (UINT64)MAX_UINT32, 1));
    assert(FnuBuildRead10(Cdb, 0x2f7840, 3));
    assert(Cdb[0] == 0x28 && Cdb[2] == 0x00 && Cdb[3] == 0x2f && Cdb[4] == 0x78 &&
           Cdb[5] == 0x40 && Cdb[8] == 3);
  }

  // CHECK CONDITION carries sense but is not a transport failure.
  ResetHc(&Hc, Dma, DmaPhys);
  Hc.ExpectCommand = 1;
  Hc.WithSense = 1;
  Status = FnuTestUnitReady(&Dev, &Ops, 1000);
  ExpectStatus("tur check condition", Status, EFI_NOT_READY);
  assert(!Poisoned);

  // Busy doorbell before submission poisons the transport.
  ResetHc(&Hc, Dma, DmaPhys);
  Hc.Reg[FNU_REG_UTRLDBR / 4] = 1;
  Status = FnuNop(&Dev, &Ops, 1000);
  ExpectStatus("busy", Status, EFI_NOT_READY);
  assert(Poisoned);
  Poisoned = FALSE;

  // Fatal interrupt before submission poisons the transport; the
  // check-before-touch clear reports NotReady exactly like the proven path.
  ResetHc(&Hc, Dma, DmaPhys);
  Hc.Reg[FNU_REG_IS / 4] = FNU_UFS_FATAL_STATUS;
  Status = FnuNop(&Dev, &Ops, 1000);
  ExpectStatus("fatal precheck", Status, EFI_NOT_READY);
  assert(Poisoned);
  Poisoned = FALSE;

  // Fatal interrupt at completion time.
  ResetHc(&Hc, Dma, DmaPhys);
  Hc.ExpectCommand = 3;
  Hc.InjectFatalOnRing = 1;
  Status = FnuNop(&Dev, &Ops, 1000);
  ExpectStatus("fatal at completion", Status, EFI_DEVICE_ERROR);
  assert(Poisoned);
  Poisoned = FALSE;

  // Doorbell stuck: timeout and quarantine; the window must never be reused.
  ResetHc(&Hc, Dma, DmaPhys);
  Hc.ExpectCommand = 3;
  Hc.StickDoorbell = 1;
  Status = FnuNop(&Dev, &Ops, 200);
  ExpectStatus("doorbell timeout", Status, EFI_TIMEOUT);
  assert(Poisoned);
  assert(FnuNop(&Dev, &Ops, 100) == EFI_NOT_READY);
  assert(Hc.Rings == 1);  // no further doorbell while quarantined
  Poisoned = FALSE;

  // Doorbell clears but the OCS never leaves "not completed".
  ResetHc(&Hc, Dma, DmaPhys);
  Hc.ExpectCommand = 3;
  Hc.OcsToReport = 0xf;
  Status = FnuNop(&Dev, &Ops, 200);
  ExpectStatus("stuck ocs", Status, EFI_TIMEOUT);
  assert(Poisoned);
  Poisoned = FALSE;

  // Non-zero OCS is an I/O error, not a timeout.
  ResetHc(&Hc, Dma, DmaPhys);
  Hc.ExpectCommand = 3;
  Hc.OcsToReport = 2;
  Status = FnuNop(&Dev, &Ops, 1000);
  ExpectStatus("ocs error", Status, EFI_DEVICE_ERROR);
  assert(!Poisoned);

  // Reject the write direction outright.
  assert(FnuSubmit(&Dev, &Ops, FNU_DIR_WRITE, 0, 100, &Value) == EFI_INVALID_PARAMETER);
  Poisoned = FALSE;

  // Argument guards.
  assert(FnuSubmit(&Dev, &Ops, FNU_DIR_READ, FNU_DATA_MAX + 4, 100, &Value) ==
         EFI_INVALID_PARAMETER);
  assert(FnuSubmit(&Dev, &Ops, FNU_DIR_READ, 2, 100, &Value) == EFI_INVALID_PARAMETER);
  assert(FnuSubmit(&Dev, &Ops, FNU_DIR_NONE, 0, 0, &Value) == EFI_INVALID_PARAMETER);
  assert(Hc.Failures == 0);
}

// ---- Queue stop planning and wait loops -------------------------------------

static void QueueScenarios(FNU_OPS *Ops) {
  assert(FnuQueueStopPlan(1, 0x0f, 0, 0, 0) == NULL);
  assert(FnuQueueStopPlan(0, 0x0f, 0, 0, 0) != NULL);
  assert(FnuQueueStopPlan(1, 0x07, 0, 0, 0) != NULL);
  assert(FnuQueueStopPlan(1, 0x0f, 1, 0, 0) != NULL);
  assert(FnuQueueStopPlan(1, 0x0f, 0, 0x100, 0) != NULL);
  assert(FnuQueueStopPlan(1, 0x0f, 0, 0, FNU_UFS_FATAL_STATUS) != NULL);
  assert(FnuQueueStopPlan(1, 0x0f, 0, 0, 1) == NULL);
  // FnuWaitRegister: pass at once, then after one stall.
  assert(FnuWaitRegister(Ops, HC_BASE + FNU_REG_UTRLRSR, 1, 0, 10));
  {
    HC *Hc = Ops->Context;
    Hc->Reg[FNU_REG_UTRLRSR / 4] = 1;
    assert(!FnuWaitRegister(Ops, HC_BASE + FNU_REG_UTRLRSR, 1, 0, 4));
    Hc->Reg[FNU_REG_UTRLRSR / 4] = 0;
    assert(FnuWaitRegister(Ops, HC_BASE + FNU_REG_UTRLRSR, 1, 0, 10));
    assert(Hc->StallCalls >= 1);
  }
}

// ---- SMMU planner ------------------------------------------------------------

typedef struct {
  UINTN Pages;
  UINT32 Idr0, Idr1, Idr2;
  UINT32 Smr[128], S2cr[128], Cbar[128], Cba2r[128], Sctlr[128];
  UINTN WriteCount;
  UINTN WriteOffset[64];
  UINT32 WriteValue[64];
  UINTN SwallowWrite;  // offset whose writes never land (readback failure)
  UINTN FaultReadOffset;  // offset whose reads return FaultReadValue
  UINT32 FaultReadValue;
  UINTN ReadCount;
} SMMU;

static UINT32 SmRead(VOID *Context, UINTN Offset) {
  SMMU *S = Context;
  S->ReadCount++;
  if (Offset == S->FaultReadOffset) return S->FaultReadValue;
  if (Offset == 0x20) return S->Idr0;
  if (Offset == 0x24) return S->Idr1;
  if (Offset == 0x28) return S->Idr2;
  if (Offset >= 0x800 && Offset < 0x800 + 512) return S->Smr[(Offset - 0x800) / 4];
  if (Offset >= 0xc00 && Offset < 0xc00 + 512) return S->S2cr[(Offset - 0xc00) / 4];
  if (Offset >= 0x1000 && Offset < 0x1000 + 512) return S->Cbar[(Offset - 0x1000) / 4];
  if (Offset >= 0x1800 && Offset < 0x1800 + 512) return S->Cba2r[(Offset - 0x1800) / 4];
  if (Offset >= S->Pages * 4096 && Offset < S->Pages * 4096 + 512 * 4096) {
    return S->Sctlr[(Offset - S->Pages * 4096) / 4096];
  }
  assert(!"unexpected SMMU offset");
  return 0;
}

static VOID SmWrite(VOID *Context, UINTN Offset, UINT32 Value) {
  SMMU *S = Context;
  if (S->WriteCount < 64) {
    S->WriteOffset[S->WriteCount] = Offset;
    S->WriteValue[S->WriteCount] = Value;
  }
  S->WriteCount++;
  if (Offset == S->SwallowWrite) return;
  if (Offset >= 0x800 && Offset < 0x800 + 512) S->Smr[(Offset - 0x800) / 4] = Value;
  else if (Offset >= 0xc00 && Offset < 0xc00 + 512) S->S2cr[(Offset - 0xc00) / 4] = Value;
  else if (Offset >= 0x1000 && Offset < 0x1000 + 512) S->Cbar[(Offset - 0x1000) / 4] = Value;
  else if (Offset >= 0x1800 && Offset < 0x1800 + 512) S->Cba2r[(Offset - 0x1800) / 4] = Value;
  else if (Offset >= S->Pages * 4096 && Offset < S->Pages * 4096 + 512 * 4096) {
    S->Sctlr[(Offset - S->Pages * 4096) / 4096] = Value;
  } else assert(!"unexpected SMMU write");
}

static void SmInit(SMMU *S, UINTN Banks) {
  memset(S, 0, sizeof(*S));
  S->Idr0 = 0x40400000U | 32;         // stage-2 support bit 30 set, 32 groups
  S->Idr1 = (1U << 28) | Banks;       // 4 global pages
  S->Idr2 = 0x5555U;                  // 48-bit widths, bit 12 set
  S->Pages = 4;
}

static void SmmuScenarios(VOID) {
  SMMU S;
  FNU_SMMU_PLAN P;
  const char *Err;
  // The planner takes the LAST free stream group, mirroring the proven code.
  UINTN LastSlot = 31;  // 32 modeled groups

  // Fresh SMMU: top bank reserved, last free stream group.
  SmInit(&S, 16);
  P = FnuPlanSmmu(FNU_SMMU_STREAM, 0x90000000ULL, FNU_DMA_BYTES, &S, SmRead);
  assert(P.Error == NULL && P.Bank == 15 && P.Slot == LastSlot && !P.Reuse);
  Err = FnuConfigureSmmu(&P, FNU_SMMU_STREAM, &S, SmRead, SmWrite);
  assert(Err == NULL);
  assert(S.Smr[LastSlot] == (0x80000000U | FNU_SMMU_STREAM));
  assert(S.S2cr[LastSlot] == 15);
  assert(S.Cbar[15] == 0x10000 && S.Cba2r[15] == 1);
  assert(S.Sctlr[15] == 0);
  assert(S.WriteCount == 5);  // sctlr, cba2r, cbar, s2cr, smr

  // Second planning round sees the mapping and reuses it without rewriting.
  {
    UINTN Before = S.WriteCount;
    P = FnuPlanSmmu(FNU_SMMU_STREAM, 0x90000000ULL, FNU_DMA_BYTES, &S, SmRead);
    assert(P.Error == NULL && P.Reuse && P.Slot == LastSlot && P.Bank == 15);
    Err = FnuConfigureSmmu(&P, FNU_SMMU_STREAM, &S, SmRead, SmWrite);
    assert(Err == NULL);
    assert(S.WriteCount == Before);
  }

  // USB's stream already maps the top bank: fall back one bank down.
  SmInit(&S, 16);
  S.Smr[3] = 0x80000000U | 0x40;
  S.S2cr[3] = 15;
  P = FnuPlanSmmu(FNU_SMMU_STREAM, 0x90000000ULL, FNU_DMA_BYTES, &S, SmRead);
  assert(P.Error == NULL && P.Bank == 14 && !P.Reuse);

  // The UEFI diagnostic starts one bank down even when the top bank is free,
  // so the USB receiver's route trial always finds the top bank untouched.
  SmInit(&S, 16);
  P = FnuPlanSmmuFrom(FNU_SMMU_STREAM, 0x90000000ULL, FNU_DMA_BYTES, &S, SmRead, 1);
  assert(P.Error == NULL && P.Bank == 14 && !P.Reuse);
  SmInit(&S, 16);
  S.Smr[3] = 0x80000000U | 0x40;
  S.S2cr[3] = 15;
  S.Smr[4] = 0x80000000U | 0x41;
  S.S2cr[4] = 14;
  P = FnuPlanSmmuFrom(FNU_SMMU_STREAM, 0x90000000ULL, FNU_DMA_BYTES, &S, SmRead, 1);
  assert(P.Error == NULL && P.Bank == 13);

  // Two valid groups matching our stream: conflict, and every bank attempt
  // still conflicts, so the first refusal is final.
  SmInit(&S, 16);
  S.Smr[2] = 0x80000000U | FNU_SMMU_STREAM;
  S.S2cr[2] = 15;
  S.Smr[3] = 0x80000000U | FNU_SMMU_STREAM;
  S.S2cr[3] = 15;
  P = FnuPlanSmmu(FNU_SMMU_STREAM, 0x90000000ULL, FNU_DMA_BYTES, &S, SmRead);
  assert(P.Error != NULL && !strcmp(P.Error, "conflicting UFS stream mapping"));

  // A masked match of our stream conflicts on every bank (the match does not
  // depend on the context bank), so the refusal is final.
  SmInit(&S, 16);
  S.Smr[2] = 0x80010000U | FNU_SMMU_STREAM;  // mask bit 0, same id
  S.S2cr[2] = 15;
  P = FnuPlanSmmu(FNU_SMMU_STREAM, 0x90000000ULL, FNU_DMA_BYTES, &S, SmRead);
  assert(P.Error != NULL && !strcmp(P.Error, "conflicting UFS stream mapping"));

  // Our own stream clean on an already-bypass top bank is reusable.
  SmInit(&S, 16);
  S.Smr[0] = 0x80000000U | FNU_SMMU_STREAM;
  S.S2cr[0] = 15;
  S.Cbar[15] = 0x10000;
  S.Cba2r[15] = 1;
  P = FnuPlanSmmu(FNU_SMMU_STREAM, 0x90000000ULL, FNU_DMA_BYTES, &S, SmRead);
  assert(P.Error == NULL && P.Reuse && P.Slot == 0 && P.Bank == 15);

  // Translation enabled on every bank is refused for good.
  SmInit(&S, 16);
  for (UINTN I = 0; I < 16; ++I) S.Sctlr[I] = 1;
  P = FnuPlanSmmu(FNU_SMMU_STREAM, 0x90000000ULL, FNU_DMA_BYTES, &S, SmRead);
  assert(P.Error != NULL && !strcmp(P.Error, "reserved context bank not bypass"));

  // Reuse with a bank left in a non-bypass state is refused (the fallback
  // then sees our stream against a foreign bank and conflicts again).
  SmInit(&S, 16);
  S.Smr[0] = 0x80000000U | FNU_SMMU_STREAM;
  S.S2cr[0] = 15;
  S.Cbar[15] = 2;
  P = FnuPlanSmmu(FNU_SMMU_STREAM, 0x90000000ULL, FNU_DMA_BYTES, &S, SmRead);
  assert(P.Error != NULL && !strcmp(P.Error, "reserved context bank not bypass"));

  // No free stream group at all.
  SmInit(&S, 16);
  for (UINTN I = 0; I < 128; ++I) S.Smr[I] = 0x80000000U | (UINT32)(0x100 + I);
  P = FnuPlanSmmu(FNU_SMMU_STREAM, 0x90000000ULL, FNU_DMA_BYTES, &S, SmRead);
  assert(P.Error != NULL && !strcmp(P.Error, "no free stream-match group"));

  // DMA beyond the SMMU input width is refused.
  SmInit(&S, 16);
  S.Idr2 = 0x0000U;  // no width bits, unsupported
  P = FnuPlanSmmu(FNU_SMMU_STREAM, 0x90000000ULL, FNU_DMA_BYTES, &S, SmRead);
  assert(P.Error != NULL && !strcmp(P.Error, "SMMU AArch64 stage 1 unsupported"));
  SmInit(&S, 16);
  P = FnuPlanSmmu(FNU_SMMU_STREAM, (1ULL << 48) - FNU_DMA_BYTES, FNU_DMA_BYTES, &S, SmRead);
  assert(P.Error == NULL);
  P = FnuPlanSmmu(FNU_SMMU_STREAM, 1ULL << 48, FNU_DMA_BYTES, &S, SmRead);
  assert(P.Error != NULL && !strcmp(P.Error, "DMA exceeds SMMU address width"));

  // Geometry guards.
  SmInit(&S, 1);
  P = FnuPlanSmmu(FNU_SMMU_STREAM, 0x90000000ULL, FNU_DMA_BYTES, &S, SmRead);
  assert(P.Error != NULL && !strcmp(P.Error, "unsupported SMMU geometry"));
  SmInit(&S, 256);
  P = FnuPlanSmmu(FNU_SMMU_STREAM, 0x90000000ULL, FNU_DMA_BYTES, &S, SmRead);
  assert(P.Error != NULL && !strcmp(P.Error, "unsupported SMMU geometry"));

  // Bounded fallback: banks 15..9 held by other streams, attempt 7 takes 8.
  SmInit(&S, 16);
  for (UINTN I = 8; I < 15; ++I) {
    S.Smr[I] = 0x80000000U | (UINT32)(0x200 + I);
    S.S2cr[I] = (UINT32)(15 - (I - 8));  // 15, 14, ..., 9
  }
  P = FnuPlanSmmu(FNU_SMMU_STREAM, 0x90000000ULL, FNU_DMA_BYTES, &S, SmRead);
  assert(P.Error == NULL && P.Bank == 8);

  // Readback failure of the bypass disable is reported, not ignored.
  SmInit(&S, 16);
  P = FnuPlanSmmu(FNU_SMMU_STREAM, 0x90000000ULL, FNU_DMA_BYTES, &S, SmRead);
  assert(P.Error == NULL);
  S.FaultReadOffset = (P.Pages + P.Bank) * 4096;
  S.FaultReadValue = 0xffffffffU;
  Err = FnuConfigureSmmu(&P, FNU_SMMU_STREAM, &S, SmRead, SmWrite);
  assert(Err != NULL && !strcmp(Err, "SMMU bypass disable readback"));
}

static void ResponseScenarios(VOID) {
  UINT8 Rsp[64];
  UINT32 Protocol, Scsi, Residual, Sense, Value;
  memset(Rsp, 0, sizeof(Rsp));
  Rsp[0] = 0x21;
  Rsp[2] = 0;
  Rsp[3] = 0;
  assert(FnuValidateResponse(Rsp, 0x21, 0, 0, &Protocol) == EFI_SUCCESS);
  Rsp[0] = 0x22;
  assert(FnuValidateResponse(Rsp, 0x21, 0, 0, &Protocol) == EFI_PROTOCOL_ERROR && Protocol == 1);
  Rsp[0] = 0x21;
  Rsp[3] = 1;
  assert(FnuValidateResponse(Rsp, 0x21, 0, 0, &Protocol) == EFI_PROTOCOL_ERROR && Protocol == 2);
  Rsp[3] = 0;
  Rsp[2] = 3;
  assert(FnuValidateResponse(Rsp, 0x21, 0, 0, &Protocol) == EFI_PROTOCOL_ERROR && Protocol == 3);
  Rsp[2] = 0;
  Rsp[8] = 1;
  assert(FnuValidateResponse(Rsp, 0x21, 0, 0, &Protocol) == EFI_PROTOCOL_ERROR && Protocol == 4);
  Rsp[8] = 0;
  Rsp[10] = 2;
  Rsp[11] = 1;
  assert(FnuValidateResponse(Rsp, 0x21, 0, 0, &Protocol) == EFI_PROTOCOL_ERROR && Protocol == 4);
  Rsp[10] = 0;
  Rsp[11] = 0;
  Rsp[6] = 0;
  Rsp[7] = 2;
  Rsp[10] = 0;
  Rsp[11] = 18;  // response segment: sense data only
  Rsp[12] = 0;
  Rsp[13] = 0;
  Rsp[14] = 0;
  Rsp[15] = 4;
  FnuParseScsi(Rsp, &Scsi, &Residual, &Sense);
  assert(Scsi == 2 && Residual == 4 && Sense == 0);
  Rsp[32] = 0;
  Rsp[33] = 14;
  Rsp[34] = 0x70;
  Rsp[36] = 0x0b;
  Rsp[46] = 0x24;
  Rsp[47] = 0x01;
  FnuParseScsi(Rsp, &Scsi, &Residual, &Sense);
  assert(Sense == ((0x0bU << 16) | (0x24U << 8) | 0x01));
  Rsp[34] = 0x72;
  Rsp[35] = 0x0b;
  Rsp[36] = 0x24;
  Rsp[37] = 0x01;
  FnuParseScsi(Rsp, &Scsi, &Residual, &Sense);
  assert(Sense == ((0x0bU << 16) | (0x24U << 8) | 0x01));

  memset(Rsp, 0, sizeof(Rsp));
  Rsp[0] = 0x36;
  Rsp[2] = 0;
  Rsp[3] = 1;
  Rsp[12] = 0x03;
  Rsp[13] = 0x02;
  PutBe32(Rsp + 20, 0x33);
  Value = 0;
  assert(FnuParseQueryResponse(Rsp, 0x03, 0x02, &Value) == EFI_SUCCESS && Value == 0x33);
  assert(FnuParseQueryResponse(Rsp, 0x03, 0x01, &Value) == EFI_PROTOCOL_ERROR);
  Rsp[12] = 0x03;
  Rsp[6] = 1;
  assert(FnuParseQueryResponse(Rsp, 0x03, 0x02, &Value) == EFI_DEVICE_ERROR);

  memset(Rsp, 0, sizeof(Rsp));
  Rsp[0] = 0x20;
  Rsp[2] = 0;
  Rsp[3] = 1;
  assert(FnuParseNopResponse(Rsp) == EFI_SUCCESS);
  Rsp[6] = 1;
  assert(FnuParseNopResponse(Rsp) == EFI_PROTOCOL_ERROR);
}

int main(int Argc, char **Argv) {
  static UINT8 Dma[FNU_DMA_BYTES];
  UINT64 DmaPhys = 0x90000000ULL;
  FNU_OPS Ops = {0};
  HC Hc;
  FILE *Vectors;
  char Line[8192];
  UINTN Cases = 0;

  assert(Argc == 2);
  memset(&Ops, 0, sizeof(Ops));
  Ops.Context = &Hc;
  Ops.Read = HcRead;
  Ops.Write = HcWrite;
  Ops.Stall = FnuStallFake;
  Ops.CacheCleanInvalidate = FnuCiv;
  Ops.CacheInvalidate = FnuInv;
  ResetHc(&Hc, Dma, DmaPhys);
  QueueScenarios(&Ops);
  CommandScenarios(Dma, DmaPhys);
  ResponseScenarios();
  SmmuScenarios();

  Vectors = fopen(Argv[1], "rb");
  assert(Vectors != NULL);
  while (fgets(Line, sizeof(Line), Vectors) != NULL) {
    // Format: "<hex data> <hex digest>"; strip the trailing newline first.
    char *Space = strchr(Line, '\n');
    if (Space != NULL) *Space = 0;
    Space = strchr(Line, ' ');
    assert(Space != NULL);
    UINTN Bytes = (UINTN)(Space - Line) / 2;
    CONST char *DigestText = Space + 1;
    UINT8 *Data = malloc(Bytes ? Bytes : 1);
    UINT8 Digest[32];
    FNU_SHA256_CTX Ctx;
    for (UINTN I = 0; I < Bytes; ++I) {
      unsigned Byte;
      assert(sscanf(Line + I * 2, "%2x", &Byte) == 1);
      Data[I] = (UINT8)Byte;
    }
    FnuSha256Init(&Ctx);
    FnuSha256Update(&Ctx, Data, Bytes);
    FnuSha256Final(&Ctx, Digest);
    for (UINTN I = 0; I < 32; ++I) {
      unsigned Byte;
      assert(sscanf(DigestText + I * 2, "%2x", &Byte) == 1);
      assert(Digest[I] == (UINT8)Byte);
    }
    // Incremental update path must agree with the one-shot result.
    if (Bytes > 3) {
      FnuSha256Init(&Ctx);
      FnuSha256Update(&Ctx, Data, 3);
      FnuSha256Update(&Ctx, Data + 3, Bytes - 3);
      FnuSha256Final(&Ctx, Digest);
      for (UINTN I = 0; I < 32; ++I) {
        unsigned Byte;
        assert(sscanf(DigestText + I * 2, "%2x", &Byte) == 1);
        assert(Digest[I] == (UINT8)Byte);
      }
    }
    free(Data);
    Cases++;
  }
  fclose(Vectors);
  assert(Cases >= 5);
  printf("fuxi-ufs-host: ok (%llu sha256 vectors)\n", (unsigned long long)Cases);
  return 0;
}
