// SPDX-License-Identifier: BSD-2-Clause-Patent
// Exercise the actual freestanding reader against independently generated disks.
#include "DataReadOnly.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { UINT8 *Bytes; UINTN Size; UINT32 Block; UINTN Reads; BOOLEAN Fail; } IMAGE;
static EFI_STATUS Read(VOID *Context, UINT64 Lba, UINTN Blocks, VOID *Buffer) {
  IMAGE *Image = Context;
  ++Image->Reads;
  if (Image->Fail) return EFI_DEVICE_ERROR;
  assert(Blocks != 0 && Lba < Image->Size / Image->Block);
  assert(Blocks <= Image->Size / Image->Block - Lba);
  memcpy(Buffer, Image->Bytes + (UINTN)Lba * Image->Block, Blocks * Image->Block);
  return EFI_SUCCESS;
}
static void PartitionBounds(const FDP_DISK *Disk, const FDP_PARTITIONS *Parts, IMAGE *Image) {
  UINT8 Buffer[4096];
  UINTN Before;
  FDP_PARTITION Bad;
  assert(Parts->Metadata.Present && Parts->Userdata.Present);
  assert(FdpReadPartition(Disk, &Parts->Metadata, 0, 1, Buffer) == EFI_SUCCESS);
  Before = Image->Reads;
  assert(FdpReadPartition(Disk, &Parts->Metadata, MAX_UINT64, 1, Buffer) == EFI_BAD_BUFFER_SIZE);
  assert(FdpReadPartition(Disk, &Parts->Metadata,
                          Parts->Metadata.Last - Parts->Metadata.First, 2, Buffer) == EFI_BAD_BUFFER_SIZE);
  assert(Image->Reads == Before);
  Bad = Parts->Metadata;
  Bad.Last = MAX_UINT64;
  assert(FdpReadPartition(Disk, &Bad, 0, 1, Buffer) == EFI_INVALID_PARAMETER);
  assert(FdpReadPartition(Disk, &Parts->Metadata, 0, 0, Buffer) == EFI_INVALID_PARAMETER);
  assert(FdpReadPartition(Disk, &Parts->Metadata, 0, 1, NULL) == EFI_INVALID_PARAMETER);
  assert(Image->Reads == Before);
}
static void Security(void) {
  UINT64 Args[8];
  UINTN I;
  BOOLEAN Available;
  const UINT32 Subjects[] = {FDP_SCM_INFO_AVAIL,FDP_SCM_ICE_SET,FDP_SCM_ICE_CLEAR,FDP_SCM_ICE_DERIVE,
    FDP_SCM_INVOKE_LEGACY,FDP_SCM_INVOKE_CALLBACK,FDP_SCM_INVOKE_OBJECT};
  for (I = 0; I < sizeof(Subjects) / sizeof(Subjects[0]); ++I) {
    assert(FdpMakeAvailabilityQuery(Subjects[I], TRUE, Args) == EFI_SUCCESS);
    assert(Args[0] == 0xc2000601 && Args[1] == 1 && Args[2] == Subjects[I]);
    assert(Args[3] == 0 && Args[4] == 0 && Args[5] == 0 && Args[6] == 0 && Args[7] == 0);
    assert(FdpMakeAvailabilityQuery(Subjects[I], FALSE, Args) == EFI_SUCCESS);
    assert(Args[0] == 0x82000601 && Args[2] == Subjects[I]);
  }
  assert(FdpMakeAvailabilityQuery(0x02000a01, TRUE, Args) == EFI_ACCESS_DENIED);
  for (I = 0; I < 8; ++I) assert(Args[I] == 0);
  assert(FdpDecodeAvailability(0, 1, &Available) == EFI_SUCCESS && Available);
  assert(FdpDecodeAvailability(0, 0, &Available) == EFI_SUCCESS && !Available);
  assert(FdpDecodeAvailability(0, 2, &Available) == EFI_PROTOCOL_ERROR && !Available);
  assert(FdpDecodeAvailability(1, 1, &Available) == EFI_NOT_READY && !Available);
  assert(FdpDecodeAvailability(MAX_UINT64, 1, &Available) == EFI_NOT_READY && !Available);
  assert(FdpDecodeAvailability(0xfffffff4, 1, &Available) == EFI_NOT_READY && !Available);
}
int main(int Argc, char **Argv) {
  FILE *File;
  IMAGE Image = {0};
  FDP_DISK Disk;
  FDP_PARTITIONS Parts;
  FDP_F2FS_GEOMETRY Geometry;
  UINT8 *Scratch = malloc(FDP_SCRATCH_BYTES);
  EFI_STATUS Status, Expected;
  long Size;
  assert(Argc == 4 && Scratch != NULL);
  Expected = (EFI_STATUS)strtoull(Argv[3], NULL, 0);
  File = fopen(Argv[1], "rb");
  assert(File != NULL && fseek(File, 0, SEEK_END) == 0);
  Size = ftell(File);
  assert(Size > 0 && fseek(File, 0, SEEK_SET) == 0);
  Image.Size = (UINTN)Size;
  Image.Bytes = malloc(Image.Size);
  assert(Image.Bytes != NULL && fread(Image.Bytes, 1, Image.Size, File) == Image.Size);
  fclose(File);
  if (strcmp(Argv[2], "f2fs") == 0) {
    memset(&Geometry, 0xa5, sizeof(Geometry));
    Status = FdpInspectF2fs(Image.Bytes, Image.Size, 16 * 1024 * 1024, &Geometry);
    if (Status != Expected) {
      fprintf(stderr, "F2FS got %llx expected %llx\n", (unsigned long long)Status,
              (unsigned long long)Expected);
      return 1;
    }
    if (!EFI_ERROR(Status)) assert(Geometry.Blocks == 4096 && Geometry.RootInode == 3);
    else assert(Geometry.Blocks == 0 && Geometry.RootInode == 0);
    free(Scratch);
    free(Image.Bytes);
    return 0;
  }
  Image.Block = (UINT32)strtoul(Argv[2], NULL, 0);
  Disk.Context = &Image;
  Disk.Read = Read;
  Disk.BlockSize = Image.Block;
  Disk.LastBlock = Image.Size / Image.Block - 1;
  assert(FdpCrc32("123456789", 9) == 0xcbf43926U);
  memset(&Parts, 0xa5, sizeof(Parts));
  Status = FdpReadGpt(&Disk, Scratch, FDP_SCRATCH_BYTES, &Parts);
  if (Status != Expected) {
    fprintf(stderr, "%s: got %llx expected %llx\n", Argv[1], (unsigned long long)Status,
            (unsigned long long)Expected);
    return 1;
  }
  if (!EFI_ERROR(Status)) PartitionBounds(&Disk, &Parts, &Image);
  else assert(!Parts.Metadata.Present && !Parts.Userdata.Present);
  Image.Fail = TRUE;
  assert(FdpReadGpt(&Disk, Scratch, FDP_SCRATCH_BYTES, &Parts) == EFI_DEVICE_ERROR);
  assert(!Parts.Metadata.Present && !Parts.Userdata.Present);
  assert(FdpReadGpt(&Disk, Scratch, 1, &Parts) == EFI_INVALID_PARAMETER);
  assert(FdpInspectF2fs(NULL, 0, 0, &Geometry) == EFI_INVALID_PARAMETER);
  memset(Scratch, 0xa5, 4096);
  assert(FdpInspectF2fs(Scratch, 4096, MAX_UINT64, &Geometry) == EFI_NOT_FOUND);
  Security();
  free(Scratch);
  free(Image.Bytes);
  return 0;
}
