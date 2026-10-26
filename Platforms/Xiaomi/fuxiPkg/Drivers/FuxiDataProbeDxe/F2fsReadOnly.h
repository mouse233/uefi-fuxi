// SPDX-License-Identifier: BSD-2-Clause-Patent
// M2 draft: original bounded readers of public F2FS v5.15 disk-format facts.
// No allocation, writes, MMIO, decryption or Linux runtime dependencies.
#ifndef FUXI_F2FS_READ_ONLY_H
#define FUXI_F2FS_READ_ONLY_H
#include "DataReadOnly.h"
#define F2R_BLOCK_BYTES 4096U
#define F2R_WORK_BYTES (4U * F2R_BLOCK_BYTES)
typedef struct {
  FDP_DISK Disk;
  FDP_PARTITION Partition;
  UINT64 Blocks, CheckpointVersion;
  UINT32 Checkpoint, Nat, Main, MainEnd, RootInode, NatSegments, SitSegments;
  UINT32 SelectedPack, NatBitmapBytes, Features;
  UINT8 NatBitmap[F2R_BLOCK_BYTES];
  BOOLEAN Prepared;
} F2R_VOLUME;
// Bootstrap only, not a mount or file-read success. This draft accepts a
// single-device 4K-block layout, no cp_payload, and a clean checkpoint.
// Known feature bits are accepted for SB/CP bootstrap ONLY. Features records
// encryption/extra-attribute/quota/verity requirements for future inode code;
// Prepared does not authorize plaintext file reads or bypass inode policy.
EFI_STATUS F2rPrepare(CONST FDP_DISK *Disk, CONST FDP_PARTITION *Partition,
                     F2R_VOLUME *Volume, VOID *Work, UINTN WorkBytes);
// Plan the on-disk NAT table read. NAT journal overlays MUST be implemented
// before callers can treat that table entry as an authoritative node mapping.
EFI_STATUS F2rPlanNatRead(CONST F2R_VOLUME *Volume, UINT32 Nid,
                         UINT64 *Block, UINTN *EntryOffset);
// Parse one already-validated, plaintext, non-inline directory block. This
// is not path lookup; caller must validate its inode and encryption policy.
EFI_STATUS F2rFindDentry(CONST VOID *Block, CONST CHAR8 *Name, UINTN NameBytes,
                        UINT32 *Inode, UINT8 *Type);
#endif
