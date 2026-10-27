// SPDX-License-Identifier: BSD-2-Clause-Patent
// Independently implemented from the public dm-default-key mapping semantics.
#include "M3DefaultKeyPlan.h"

EFI_STATUS FdmPlanMetadataRead(CONST FDP_DISK *Disk, CONST FDP_PARTITION *Part,
                               CONST FDM_MAPPING *M, UINT64 Logical512,
                               UINT64 Sectors512, FDM_PLAN *Plan) {
  UINT64 Relative, Span, PartBlocks, MappingStart, MappingBlocks;
  UINT64 RelativeBlocks, Blocks, Iv, OffsetBlocks;
  if (!Plan) return EFI_INVALID_PARAMETER;
  Plan->DiskLba=0; Plan->FirstDun=0; Plan->Blocks=0;
  if (!Disk || !Part || !M || !Part->Present || Part->First>Part->Last ||
      Part->Last>Disk->LastBlock || !Sectors512) return EFI_INVALID_PARAMETER;
  // The first M3 slice is intentionally restricted to verified 4 KiB UFS,
  // AES-256-XTS, hardware-wrapped v0, iv_large_sectors mappings.
  if (!M->MappingVerified || Disk->BlockSize!=4096 || M->CryptoUnitBytes!=4096 ||
      !M->IvLargeSectors || !M->Aes256Xts || !M->WrappedKeyV0)
    return EFI_UNSUPPORTED;
  if (!M->TargetLength512 || (M->TargetBegin512&7) || (M->TargetLength512&7) ||
      (M->DeviceStart512&7) || (M->IvOffset512&7) || (Sectors512&7))
    return EFI_INVALID_PARAMETER;
  if (M->TargetLength512-1>MAX_UINT64-M->TargetBegin512 ||
      M->TargetLength512-1>MAX_UINT64-M->IvOffset512)
    return EFI_INVALID_PARAMETER;
  Span=Part->Last-Part->First;
  if (Span==MAX_UINT64) return EFI_INVALID_PARAMETER;
  PartBlocks=Span+1;
  MappingStart=M->DeviceStart512/8;
  MappingBlocks=M->TargetLength512/8;
  if (MappingStart>PartBlocks || MappingBlocks>PartBlocks-MappingStart)
    return EFI_INVALID_PARAMETER;
  if (Logical512<M->TargetBegin512) return EFI_INVALID_PARAMETER;
  Relative=Logical512-M->TargetBegin512;
  if ((Relative&7) || Relative>=M->TargetLength512 ||
      Sectors512>M->TargetLength512-Relative) return EFI_INVALID_PARAMETER;
  RelativeBlocks=Relative/8; Blocks=Sectors512/8;
  if ((UINT64)(UINTN)Blocks!=Blocks) return EFI_INVALID_PARAMETER;
  OffsetBlocks=MappingStart+RelativeBlocks;
  Iv=M->IvOffset512+Relative;
  Plan->DiskLba=Part->First+OffsetBlocks;
  Plan->FirstDun=Iv/8;
  Plan->Blocks=(UINTN)Blocks;
  return EFI_SUCCESS;
}
