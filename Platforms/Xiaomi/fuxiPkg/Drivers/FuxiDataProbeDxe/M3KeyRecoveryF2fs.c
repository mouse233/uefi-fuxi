// SPDX-License-Identifier: BSD-2-Clause-Patent
#include "M3KeyRecoveryF2fs.h"
STATIC VOID Erase(VOID *Memory, UINTN Bytes) {
  volatile UINT8 *P = Memory;
  while (Bytes-- != 0) *P++ = 0;
}
EFI_STATUS FkrReadF2fsFile(VOID *Context, FKR_FILE Which, VOID *Buffer,
                           UINTN Capacity, UINTN *Bytes) {
  STATIC CONST CHAR8 *Paths[] = {
    "/vold/metadata_encryption/key/version",
    "/vold/metadata_encryption/key/secdiscardable",
    "/vold/metadata_encryption/key/keymaster_key_blob",
    "/vold/metadata_encryption/key/encrypted_key"
  };
  FKR_F2FS_CONTEXT *C = Context;
  F2R_FILE File;
  EFI_STATUS Status;
  UINTN Got = 0;
  if (Bytes == NULL) return EFI_INVALID_PARAMETER;
  *Bytes = 0;
  if (C == NULL || C->Volume == NULL || C->Work == NULL ||
      C->WorkBytes < F2R_WORK_BYTES || Buffer == NULL || Capacity == 0 ||
      (UINTN)Which >= sizeof(Paths)/sizeof(Paths[0])) return EFI_INVALID_PARAMETER;
  Status = F2rLookup(C->Volume, Paths[Which], &File, C->Work, C->WorkBytes);
  if (EFI_ERROR(Status)) goto Done;
  if (File.Mode != 0x8000) { Status = EFI_UNSUPPORTED; goto Done; }
  if (File.Bytes == 0 || File.Bytes > Capacity) { Status = EFI_BAD_BUFFER_SIZE; goto Done; }
  Status = F2rReadFile(&File, 0, Buffer, (UINTN)File.Bytes, &Got, C->Work, C->WorkBytes);
  if (EFI_ERROR(Status)) goto Done;
  if (Got != File.Bytes) { Status = EFI_DEVICE_ERROR; goto Done; }
  *Bytes = Got;
Done:
  Erase(&File, sizeof(File));
  Erase(C->Work, C->WorkBytes);
  if (EFI_ERROR(Status)) Erase(Buffer, Capacity);
  return Status;
}
