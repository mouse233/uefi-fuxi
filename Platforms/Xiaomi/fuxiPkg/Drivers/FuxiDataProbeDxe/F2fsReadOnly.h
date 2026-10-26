// SPDX-License-Identifier: BSD-2-Clause-Patent
// M2 metadata reader: original bounded readers of public F2FS v5.15 disk-format facts.
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
  UINT32 SelectedPack, NatBitmapBytes, Features, CheckpointFlags;
  UINT8 NatBitmap[F2R_BLOCK_BYTES];
  UINT16 NatJournalCount;
  UINT8 NatJournal[38U * 13U];
  BOOLEAN Prepared;
} F2R_VOLUME;
// Bootstrap only, not a mount or file-read success. This reader accepts a
// single-device 4K-block layout, no cp_payload, and a clean checkpoint.
// Known feature bits describe volume capabilities; file access separately
// checks inode policy. Prepared never bypasses encryption/verity restrictions.
EFI_STATUS F2rPrepare(CONST FDP_DISK *Disk, CONST FDP_PARTITION *Partition,
                     F2R_VOLUME *Volume, VOID *Work, UINTN WorkBytes);
// Plan a NAT table read. F2rOpenInode applies the selected checkpoint journal
// before consulting this table; this low-level address plan alone is not a mapping.
EFI_STATUS F2rPlanNatRead(CONST F2R_VOLUME *Volume, UINT32 Nid,
                         UINT64 *Block, UINTN *EntryOffset);
// Parse one already-validated, plaintext, non-inline directory block. This
// is not path lookup; caller must validate its inode and encryption policy.
EFI_STATUS F2rFindDentry(CONST VOID *Block, CONST CHAR8 *Name, UINTN NameBytes,
                        UINT32 *Inode, UINT8 *Type);
// A prepared volume describes a clean offline checkpoint, not a live mount.
// Caller-owned workspace and result/output buffers must be disjoint. APIs are
// synchronous; callbacks must not reenter the volume or mutate these objects.
typedef struct {
  CONST F2R_VOLUME *Volume;
  UINT64 Bytes;
  UINT32 Inode, AddressOffset, AddressCount, InlineOffset, InlineBytes;
  UINT16 Mode;
  UINT8 Inline;
  BOOLEAN Valid;
  UINT8 Node[F2R_BLOCK_BYTES];
} F2R_FILE;
typedef EFI_STATUS (*F2R_DENTRY_VISITOR)(VOID *Context, CONST CHAR8 *Name,
                                      UINTN Length, UINT32 Inode, UINT8 Type);
EFI_STATUS F2rOpenInode(CONST F2R_VOLUME *Volume, UINT32 Inode, F2R_FILE *File,
                        VOID *Work, UINTN WorkBytes);
// Absolute paths only, no symlinks or dot components, max 1024 bytes/16 levels.
EFI_STATUS F2rLookup(CONST F2R_VOLUME *Volume, CONST CHAR8 *Path, F2R_FILE *File,
                     VOID *Work, UINTN WorkBytes);
// Regular files only. On IO/format failure, zero the requested output range and
// return ReadBytes=0. Holes read as zero; NEW/COMPRESS addresses are rejected.
EFI_STATUS F2rReadFile(CONST F2R_FILE *File, UINT64 Offset, VOID *Buffer,
                       UINTN Bytes, UINTN *ReadBytes, VOID *Work, UINTN WorkBytes);
// Inline or block directories; bounded to 256 blocks. Name is length-delimited.
EFI_STATUS F2rListDirectory(CONST F2R_FILE *Directory, F2R_DENTRY_VISITOR Visitor,
                            VOID *Context, VOID *Work, UINTN WorkBytes);
#endif
