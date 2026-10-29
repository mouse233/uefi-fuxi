// SPDX-License-Identifier: BSD-2-Clause-Patent
#ifndef FUXI_M3_KEY_RECOVERY_F2FS_H
#define FUXI_M3_KEY_RECOVERY_F2FS_H
#include "M3KeyRecovery.h"
#include "F2fsReadOnly.h"
typedef struct {
  CONST F2R_VOLUME *Volume;
  VOID *Work;
  UINTN WorkBytes;
} FKR_F2FS_CONTEXT;
// Fixed files only, no directory discovery/hash/prefix logging or write API.
EFI_STATUS FkrReadF2fsFile(VOID *Context, FKR_FILE File, VOID *Buffer,
                           UINTN Capacity, UINTN *Bytes);
#endif
