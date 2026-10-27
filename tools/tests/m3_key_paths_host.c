// SPDX-License-Identifier: BSD-2-Clause-Patent
// Exercises the production F2FS reader on the fixed metadata key paths.
#include "F2fsReadOnly.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *Image;

static EFI_STATUS Read(VOID *Context, UINT64 Lba, UINTN Count, VOID *Buffer) {
  (void)Context;
  assert(Count == 1 && Lba < 32768);
  if (fseek(Image, (long)(Lba * 4096), SEEK_SET) ||
      fread(Buffer, 4096, 1, Image) != 1) return EFI_DEVICE_ERROR;
  return EFI_SUCCESS;
}

typedef struct {
  CHAR8 Name[8][256];
  UINTN Length[8];
  UINT8 Type[8];
  UINTN Count;
} LIST;

static EFI_STATUS Collect(VOID *Context, CONST CHAR8 *Name, UINTN Length,
                          UINT32 Inode, UINT8 Type) {
  LIST *List = Context;
  (void)Inode;
  if ((Length == 1 && Name[0] == '.') ||
      (Length == 2 && Name[0] == '.' && Name[1] == '.')) return EFI_SUCCESS;
  assert(List->Count < 8 && Length && Length <= 255);
  memcpy(List->Name[List->Count], Name, Length);
  List->Name[List->Count][Length] = 0;
  List->Length[List->Count] = Length;
  List->Type[List->Count] = Type;
  ++List->Count;
  return EFI_SUCCESS;
}

static int Has(const LIST *List, const char *Name, UINT8 Type) {
  UINTN I;
  for (I = 0; I < List->Count; ++I)
    if (strlen(Name) == List->Length[I] && !memcmp(List->Name[I], Name, List->Length[I]) &&
        List->Type[I] == Type) return 1;
  return 0;
}

int main(int Argc, char **Argv) {
  F2R_VOLUME Volume = {0};
  F2R_FILE File = {0};
  LIST List;
  UINT8 Work[F2R_WORK_BYTES], One = 0, Blob[96];
  UINTN Got = 0, I;
  FDP_DISK Disk = {NULL, Read, 4096, 32767};
  FDP_PARTITION Part = {0, 32767, TRUE};

  assert(Argc == 2);
  Image = fopen(Argv[1], "rb");
  assert(Image);
  assert(F2rPrepare(&Disk, &Part, &Volume, Work, sizeof(Work)) == EFI_SUCCESS);

  memset(&List, 0, sizeof(List));
  assert(F2rLookup(&Volume, "/vold/metadata_encryption/key", &File, Work, sizeof(Work)) == EFI_SUCCESS);
  assert(File.Mode == 0x4000);
  assert(F2rListDirectory(&File, Collect, &List, Work, sizeof(Work)) == EFI_SUCCESS);
  assert(List.Count == 2 && Has(&List, "blob", 1) && Has(&List, "version", 1));

  assert(F2rLookup(&Volume, "/vold/metadata_encryption/key/version", &File, Work, sizeof(Work)) == EFI_SUCCESS);
  assert(File.Mode == 0x8000 && File.Bytes == 1);
  assert(F2rReadFile(&File, 0, &One, 1, &Got, Work, sizeof(Work)) == EFI_SUCCESS && Got == 1 && One == '1');

  assert(F2rLookup(&Volume, "/vold/metadata_encryption/key/blob", &File, Work, sizeof(Work)) == EFI_SUCCESS);
  assert(File.Mode == 0x8000 && File.Bytes == sizeof(Blob));
  assert(F2rReadFile(&File, 0, Blob, sizeof(Blob), &Got, Work, sizeof(Work)) == EFI_SUCCESS && Got == sizeof(Blob));
  for (I = 0; I < sizeof(Blob); ++I) assert(Blob[I] == (UINT8)((I * 7 + 0xa5) & 0xff));

  assert(F2rLookup(&Volume, "/vold/metadata_encryption/missing", &File, Work, sizeof(Work)) == EFI_NOT_FOUND);
  assert(F2rLookup(&Volume, "/vold/metadata_encryption/key/version/extra", &File, Work, sizeof(Work)) != EFI_SUCCESS);
  printf("PASS metadata key paths entries=%u blob=%u\n", (unsigned)List.Count, (unsigned)sizeof(Blob));
  fclose(Image);
  return 0;
}
