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
// Compare independent reads into disjoint caller-owned buffers. Stops at the
// first transport error or mismatch; output count is the completed read count.
EFI_STATUS FdpVerifyPartitionRead(CONST FDP_DISK *Disk, CONST FDP_PARTITION *Partition,
                                  UINT64 RelativeLba, UINTN Blocks, VOID *First,
                                  VOID *Repeat, UINTN BufferBytes, UINTN Reads,
                                  UINTN *Completed);
// Signature/geometry inspection only. This neither mounts nor authenticates F2FS.
EFI_STATUS FdpInspectF2fs(CONST VOID *First4k, UINTN Bytes,
                         UINT64 PartitionBytes, FDP_F2FS_GEOMETRY *Geometry);

// These are query subjects, never the SMC function actually invoked.
#define FDP_SCM_INFO_AVAIL 0x02000601U
#define FDP_SCM_ICE_SET    0x02001005U
#define FDP_SCM_ICE_CLEAR  0x02001006U
#define FDP_SCM_ICE_DERIVE 0x02001007U
#define FDP_SCM_BRIDGE_ENABLE 0x02000c1cU
#define FDP_SCM_BRIDGE_DELETE 0x02000c1dU
#define FDP_SCM_BRIDGE_CREATE 0x02000c1eU
#define FDP_SCM_INVOKE_LEGACY 0x32000600U
#define FDP_SCM_INVOKE_CALLBACK 0x32000601U
#define FDP_SCM_INVOKE_OBJECT 0x32000602U
EFI_STATUS FdpMakeAvailabilityQuery(UINT32 Subject, BOOLEAN Smc64, UINT64 Args[8]);
EFI_STATUS FdpDecodeAvailability(UINT64 Result0, UINT64 Result1,
                                 BOOLEAN *Available);

// Fixed qcom-scm.ko bridge calls use type=0: standard SMC64, owner=2.
// Four scalar arguments fit x2..x5. Five or more require an extended buffer;
// this bounded builder rejects them. INFO has its own unchanged fast builder.
#define FDP_SCM64_FNID_PREFIX 0x42000000ULL
#define FDP_SCM64_MAX_ARGS 4U
typedef struct {
  UINT32 Svc;
  UINT32 Cmd;
  UINT32 ArgCount;
  UINT64 Args[FDP_SCM64_MAX_ARGS];
} FDP_SCM64_CALL;

EFI_STATUS FdpBuildScm64(CONST FDP_SCM64_CALL *Call, UINT64 Regs[8]);
// Bridge descriptors use service 0x0c with owner 2: enable 0x1c takes no
// argument, delete 0x1d takes the handle and create 0x1e takes four. Create
// repeats the physical address with the flag word and carries the VM count at
// bit 9 of the size word. The vendor module conditionally adds 0x1a from
// internal state; that conditional is not modelled here.
EFI_STATUS FdpBuildBridgeEnable(UINT64 Regs[8]);
EFI_STATUS FdpBuildBridgeDelete(UINT64 Handle, UINT64 Regs[8]);
EFI_STATUS FdpBuildBridgeCreate(UINT64 Phys, UINT64 Size, UINT32 VmCount,
                                UINT64 VmBits, UINT64 Regs[8]);
// Fixed wrapper: a0=SCM status, low32(a1)=service result, a2=64-bit handle.
// Accept only the conservative zero-result/nonzero-handle subset, no retry.
EFI_STATUS FdpDecodeBridgeCreate(UINT64 Result0, UINT64 Result1,
                                 UINT64 Result2, UINT64 *Handle);
#endif
