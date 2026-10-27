// SPDX-License-Identifier: BSD-2-Clause-Patent
// Register facts and the bounded read-only command core for the fuxi UFS host
// (SM8550). Offsets and sequences are transcribed from the NativeUfs driver
// proven on this device (unixnu-source drivers/NativeUfs; hardware 2026-10-17
// and 2026-10-23). Nothing here performs MMIO, allocation or cache work: the
// caller supplies ordered callbacks. Only direction-2 (device to host) data
// transfers exist; there is no write path and no key operation.
#ifndef FUXI_NATIVE_UFS_CORE_H
#define FUXI_NATIVE_UFS_CORE_H
#include <Uefi.h>

// Board windows (clock-controller@100000, ufshc@1d84000, apps_smmu@15000000).
#define FNU_GCC_BASE            0x00100000ULL
#define FNU_UFS_HC_BASE         0x01d84000ULL
#define FNU_UFS_HC_SIZE         0x3000ULL
#define FNU_SMMU_BASE           0x15000000ULL
#define FNU_SMMU_SIZE           0xd0000ULL
#define FNU_SMMU_STREAM         0x60U  // iommus = <&apps_smmu 0x60 0x0>

// GCC read-only report registers (GccUfs.h facts; no write is performed).
#define FNU_GCC_UFS_PHY_GDSCR   0x77004U
#define FNU_GCC_MEM_PHY_GDSCR   0x9e000U
#define FNU_GCC_UFS_PHY_AXI     0x77018U
#define FNU_GCC_UFS_PHY_AHB     0x77024U
#define FNU_GCC_UFS_PHY_TXSYM0  0x77028U
#define FNU_GCC_UFS_PHY_RXSYM0  0x7702cU
#define FNU_GCC_UFS_PHY_UNIPRO  0x77068U
#define FNU_GCC_UFS_PHY_ICE     0x77074U
#define FNU_GCC_UFS_PHY_AUX     0x770b0U
#define FNU_GCC_AGGRE_UFS_AXI   0x770e4U

// Host controller register offsets as this hardware behaves (NativeUfs facts;
// the request list lives at 0x50/0x54, the transfer doorbell at 0x58 and the
// run/stop readback register at 0x60).
#define FNU_REG_CAP             0x00U
#define FNU_REG_VER             0x08U
#define FNU_REG_AHIT            0x18U
#define FNU_REG_IS              0x20U
#define FNU_REG_IE              0x24U
#define FNU_REG_HCS             0x30U
#define FNU_REG_HCE             0x34U
#define FNU_REG_UTRLBA          0x50U
#define FNU_REG_UTRLBAU         0x54U
#define FNU_REG_UTRLDBR         0x58U
#define FNU_REG_UTRLRSR         0x60U
#define FNU_REG_UTMRLDBR        0x78U
#define FNU_REG_UIC(n)          (0x38U + 4U * (n))
#define FNU_UFS_FATAL_STATUS    0x71880U

// Shared DMA window layout (RootTransportLayout.h facts). One request slot.
#define FNU_UCD_OFFSET          4096U
#define FNU_RSP_OFFSET          512U
#define FNU_PRDT_OFFSET         1024U
#define FNU_DATA_OFFSET         8192U
#define FNU_DATA_MAX            131072U
#define FNU_DMA_BYTES           (FNU_DATA_OFFSET + FNU_DATA_MAX)
#define FNU_DATA_LBAS           (FNU_DATA_MAX / 4096U)

// UTRD data direction; direction 1 (host to device) is rejected by this core.
#define FNU_DIR_NONE            0U
#define FNU_DIR_WRITE           1U
#define FNU_DIR_READ            2U

typedef struct FNU_OPS_ FNU_OPS;
struct FNU_OPS_ {
  VOID *Context;
  UINT32 (*Read)(FNU_OPS *Ops, UINT64 Phys);
  VOID (*Write)(FNU_OPS *Ops, UINT64 Phys, UINT32 Value);
  VOID (*Stall)(FNU_OPS *Ops, UINTN Microseconds);
  VOID (*CacheCleanInvalidate)(FNU_OPS *Ops, VOID *Va, UINTN Bytes);
  VOID (*CacheInvalidate)(FNU_OPS *Ops, VOID *Va, UINTN Bytes);
};

typedef struct {
  UINT64 HcPhys;   // host controller register base
  UINT8 *Dma;      // virtual address of the shared window
  UINT64 DmaPhys;  // physical address of the shared window
  BOOLEAN *Poisoned;  // set after any completion doubt; never cleared here
} FNU_DEVICE;

typedef struct {
  UINT32 Polls;
  UINT32 DoorbellSeen;
  UINT32 InterruptSeen;
  UINT32 Ocs;
} FNU_POLL_STATE;
typedef enum { FNU_POLL_COMPLETED, FNU_POLL_FATAL, FNU_POLL_TIMEOUT } FNU_POLL_END;

// Standard UFS capability inspection only; never reads the crypto config array.
#define FNU_CRYPTO_CAP_LIMIT 8U
typedef struct {
  UINT32 Ccap;
  UINT32 Entries[FNU_CRYPTO_CAP_LIMIT];
  UINT32 EntryCount;
  UINT32 AdvertisedCount;
} FNU_CRYPTO_CAP_REPORT;
EFI_STATUS FnuReadCryptoCapabilities(FNU_OPS *Ops, UINT32 Cap, UINT32 Hce,
                                     FNU_CRYPTO_CAP_REPORT *Report);

// Find a standard AES-256-XTS/4096 capability; does not inspect or reserve slots.
EFI_STATUS FnuFindXts4096Capability(CONST FNU_CRYPTO_CAP_REPORT *Report,
                                    UINT32 *Index);

// Command area: zero the 32-byte UTRD and the command/response/PRDT area.
VOID FnuClearCommandArea(UINT8 *Dma);
// UTRD for slot 0 plus the single-entry PRDT when DataBytes > 0.
VOID FnuFillUtrd(UINT8 *Dma, UINT64 DmaPhys, UINT32 Direction, UINT32 DataBytes);
// Command UPIU (type 0x01). Flags 0x40 read, 0x20 write, 0x00 no data.
VOID FnuFillCommandUpiu(UINT8 *Dma, UINT8 Lun, UINT8 Flags, CONST UINT8 *Cdb,
                        UINTN CdbBytes, UINT32 DataBytes, UINT8 Tag);
// NOP OUT (type 0x00) and standard read query requests (type 0x16).
VOID FnuFillNopUpiu(UINT8 *Dma, UINT8 Tag);
VOID FnuFillQueryUpiu(UINT8 *Dma, UINT8 Opcode, UINT8 Idn, UINT8 Tag);

// READ(10) CDB for 4096-byte logical blocks; FALSE beyond the 32-bit LBA range.
BOOLEAN FnuBuildRead10(UINT8 Cdb[10], UINT64 Lba, UINTN Blocks);

// Response UPIU validation before status bytes are interpreted. Protocol
// codes on failure: 1 type, 2 tag, 3 LUN, 4 length/EHS.
EFI_STATUS FnuValidateResponse(CONST UINT8 *Rsp, UINT8 Type, UINT8 Lun, UINT8 Tag,
                               UINT32 *ProtocolError);
// SCSI status (rsp[6..7]), residual and sense key/ASC/ASCQ from a response
// whose header FnuValidateResponse accepted.
VOID FnuParseScsi(CONST UINT8 *Rsp, UINT32 *ScsiStatus, UINT32 *Residual, UINT32 *Sense);
// Query response value field; opcode/idn echo must match.
EFI_STATUS FnuParseQueryResponse(CONST UINT8 *Rsp, UINT8 Opcode, UINT8 Idn, UINT32 *Value);
// NOP response: no data segment and a zero result field.
EFI_STATUS FnuParseNopResponse(CONST UINT8 *Rsp);

// Pre-write takeover gate, mirroring the proven hostStopQueue checks.
CONST CHAR8 *FnuQueueStopPlan(UINT32 Hce, UINT32 Hcs, UINT32 Doorbell,
                              UINT32 TaskDoorbell, UINT32 Interrupt);
// Poll until (reg & Mask) == Value; Attempts stalls of 10 microseconds.
BOOLEAN FnuWaitRegister(FNU_OPS *Ops, UINT64 Phys, UINT32 Mask, UINT32 Value, UINTN Attempts);

// Single-slot completion policy (TransferPoll.h): no resubmission. MaxPolls
// stalls of 2 microseconds bound the wait.
FNU_POLL_END FnuPollTransfer(FNU_DEVICE *Dev, FNU_OPS *Ops, UINTN MaxPolls,
                             FNU_POLL_STATE *State);

// Submit the command already placed in the DMA window through slot 0. Poison
// on busy, fatal status or any completion doubt; never free or reuse the
// window after that. Data direction must be 0 or 2.
EFI_STATUS FnuSubmit(FNU_DEVICE *Dev, FNU_OPS *Ops, UINT32 Direction, UINT32 DataBytes,
                     UINTN MaxPolls, UINT32 *Ocs);
// Transport proof: NOP OUT with tag 1 and a zero result field.
EFI_STATUS FnuNop(FNU_DEVICE *Dev, FNU_OPS *Ops, UINTN MaxPolls);
// SCSI commands this driver exposes. No-data: TEST UNIT READY (0x00) on LUN 0
// and START STOP UNIT with power condition ACTIVE (0x1b) on the device LU
// 0xd0 only. Reads: READ CAPACITY(10) and READ(10) of 4096-byte blocks.
EFI_STATUS FnuTestUnitReady(FNU_DEVICE *Dev, FNU_OPS *Ops, UINTN MaxPolls);
EFI_STATUS FnuStartStopUnit(FNU_DEVICE *Dev, FNU_OPS *Ops, UINTN MaxPolls);
EFI_STATUS FnuReadCapacity(FNU_DEVICE *Dev, FNU_OPS *Ops, UINT32 *LastLba,
                           UINT32 *BlockBytes, UINTN MaxPolls);
EFI_STATUS FnuReadBlocks(FNU_DEVICE *Dev, FNU_OPS *Ops, UINT64 Lba, UINTN Blocks,
                         VOID *Dst, UINTN MaxPolls);
// UFS query read requests: READ ATTRIBUTE (0x03) and READ FLAG (0x05) only.
EFI_STATUS FnuQueryRead(FNU_DEVICE *Dev, FNU_OPS *Ops, UINT8 Opcode, UINT8 Idn,
                        UINT32 *Value, UINTN MaxPolls);

// ARM SMMUv2 planner and configuration (SmmuTakeover.h facts), callback form.
typedef UINT32 (*FNU_SMMU_READ)(VOID *Context, UINTN Offset);
typedef VOID (*FNU_SMMU_WRITE)(VOID *Context, UINTN Offset, UINT32 Value);
typedef struct {
  UINT32 Slot;       // 0xffffffff = none
  UINT32 Bank;
  UINT32 Pages;
  UINT32 Smr;
  UINT32 S2Cr;
  BOOLEAN Reuse;
  CONST CHAR8 *Error;
} FNU_SMMU_PLAN;

FNU_SMMU_PLAN FnuPlanSmmuBank(UINT16 Stream, UINT64 Dma, UINT64 Bytes, VOID *Context,
                              FNU_SMMU_READ Read, UINTN BankFromTop);
FNU_SMMU_PLAN FnuPlanSmmu(UINT16 Stream, UINT64 Dma, UINT64 Bytes, VOID *Context,
                          FNU_SMMU_READ Read);
// Same fallback walk starting at a given bank-from-top offset. The UEFI
// diagnostic starts at 1 so the topmost bank stays exactly as ABL left it
// for the USB receiver's route trial.
FNU_SMMU_PLAN FnuPlanSmmuFrom(UINT16 Stream, UINT64 Dma, UINT64 Bytes, VOID *Context,
                              FNU_SMMU_READ Read, UINTN BankFromTop);
// Requires a quiesced queue. Refuses banks another valid stream maps.
CONST CHAR8 *FnuConfigureSmmu(CONST FNU_SMMU_PLAN *Plan, UINT16 Stream, VOID *Context,
                              FNU_SMMU_READ Read, FNU_SMMU_WRITE Write);

#endif
