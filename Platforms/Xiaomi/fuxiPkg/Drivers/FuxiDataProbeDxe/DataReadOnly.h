// SPDX-License-Identifier: BSD-2-Clause-Patent
// Independent, bounded readers. No Linux code or vendor binaries are linked.
#ifndef FUXI_DATA_READ_ONLY_H
#define FUXI_DATA_READ_ONLY_H
#include <Uefi.h>

#define FDP_MAX_GPT_BYTES 65536U
#define FDP_MAX_BLOCK_SIZE 4096U
#define FDP_SCRATCH_BYTES (FDP_MAX_GPT_BYTES + FDP_MAX_BLOCK_SIZE)

typedef EFI_STATUS (*FDP_READ_BLOCKS)(VOID *Context, UINT64 Lba,
                                     UINTN Blocks, VOID *Buffer);
typedef struct {
  VOID *Context;
  FDP_READ_BLOCKS Read;
  UINT32 BlockSize;
  UINT64 LastBlock;
} FDP_DISK;
typedef struct {
  UINT64 First;
  UINT64 Last;
  BOOLEAN Present;
} FDP_PARTITION;
typedef struct {
  FDP_PARTITION Metadata;
  FDP_PARTITION Userdata;
} FDP_PARTITIONS;
typedef struct {
  UINT64 Blocks;
  UINT32 RootInode;
  UINT32 CheckpointBlock;
  UINT32 NatBlock;
  UINT32 MainBlock;
} FDP_F2FS_GEOMETRY;

UINT32 FdpCrc32(CONST VOID *Data, UINTN Bytes);
EFI_STATUS FdpReadGpt(CONST FDP_DISK *Disk, VOID *Scratch, UINTN ScratchBytes,
                      FDP_PARTITIONS *Partitions);
EFI_STATUS FdpReadPartition(CONST FDP_DISK *Disk, CONST FDP_PARTITION *Partition,
                            UINT64 RelativeLba, UINTN Blocks, VOID *Buffer);
// Signature/geometry inspection only. This neither mounts nor authenticates F2FS.
EFI_STATUS FdpInspectF2fs(CONST VOID *First4k, UINTN Bytes,
                         UINT64 PartitionBytes, FDP_F2FS_GEOMETRY *Geometry);

// These are query subjects, never the SMC function actually invoked.
#define FDP_SCM_INFO_AVAIL 0x02000601U
#define FDP_SCM_ICE_SET    0x02001005U
#define FDP_SCM_ICE_CLEAR  0x02001006U
#define FDP_SCM_ICE_DERIVE 0x02001007U
EFI_STATUS FdpMakeAvailabilityQuery(UINT32 Subject, BOOLEAN Smc64, UINT64 Args[8]);
EFI_STATUS FdpDecodeAvailability(UINT64 Result0, UINT64 Result1,
                                 BOOLEAN *Available);
#endif
