// SPDX-License-Identifier: BSD-2-Clause-Patent
// Metadata-only address planning. No IO, keys, SMC or ICE operations.
#ifndef FUXI_M3_DEFAULT_KEY_PLAN_H
#define FUXI_M3_DEFAULT_KEY_PLAN_H

#include "DataReadOnly.h"

// All sector fields use Linux device-mapper's 512-byte sector units.
// The caller must obtain and verify the live mapping and device identity;
// fstab defaults or a TWRP example alone are insufficient evidence.
typedef struct {
  UINT64 TargetBegin512;
  UINT64 TargetLength512;
  UINT64 DeviceStart512;
  UINT64 IvOffset512;
  UINT32 CryptoUnitBytes;
  BOOLEAN IvLargeSectors;
  BOOLEAN Aes256Xts;
  BOOLEAN WrappedKeyV0;
  BOOLEAN MappingVerified;
} FDM_MAPPING;

typedef struct {
  UINT64 DiskLba;
  UINT64 FirstDun;
  UINTN Blocks;
} FDM_PLAN;

// Only for filesystem metadata covered by dm-default-key, never for file
// contents using fscrypt's override. Inputs and output must not overlap.
// A successful plan only proves arithmetic/bounds, not key availability,
// plaintext correctness or permission to access hardware.
EFI_STATUS FdmPlanMetadataRead(CONST FDP_DISK *Disk, CONST FDP_PARTITION *Part,
                               CONST FDM_MAPPING *Mapping, UINT64 Logical512,
                               UINT64 Sectors512, FDM_PLAN *Plan);
#endif
